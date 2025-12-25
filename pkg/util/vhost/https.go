// Copyright 2016 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vhost

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	libnet "github.com/fatedier/golib/net"
)

// ACMEProvider is an interface for ACME certificate management.
// This is used to decouple the vhost package from the acme package.
type ACMEProvider interface {
	GetCertificate() func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// HTTPSMuxerOption is a function that configures an HTTPSMuxer.
type HTTPSMuxerOption func(*HTTPSMuxer)

// WithACMEProvider sets the ACME provider for dynamic certificate management.
func WithACMEProvider(provider ACMEProvider) HTTPSMuxerOption {
	return func(m *HTTPSMuxer) {
		m.acmeProvider = provider
	}
}

// WithHTTPHandler sets the HTTP handler for TLS-terminated connections.
// This is used to serve HTTP proxies over HTTPS with ACME certificates.
func WithHTTPHandler(handler http.Handler) HTTPSMuxerOption {
	return func(m *HTTPSMuxer) {
		m.httpHandler = handler
	}
}

type HTTPSMuxer struct {
	*Muxer
	acmeProvider ACMEProvider
	httpHandler  http.Handler
}

func NewHTTPSMuxer(listener net.Listener, timeout time.Duration, opts ...HTTPSMuxerOption) (*HTTPSMuxer, error) {
	mux, err := NewMuxer(listener, GetHTTPSHostname, timeout)
	if err != nil {
		return nil, err
	}

	httpsMuxer := &HTTPSMuxer{Muxer: mux}
	for _, opt := range opts {
		opt(httpsMuxer)
	}

	// Set fail hook with ACME-aware TLS config
	mux.SetFailHookFunc(httpsMuxer.vhostFailedWithACME)

	return httpsMuxer, nil
}

// vhostFailedWithACME handles failed vhost connections with optional ACME certificate lookup.
// If an HTTP handler is configured, it will terminate TLS and forward the request.
func (m *HTTPSMuxer) vhostFailedWithACME(c net.Conn) {
	if m.acmeProvider == nil {
		c.Close()
		return
	}

	tlsCfg := &tls.Config{
		GetCertificate: m.acmeProvider.GetCertificate(),
	}

	// If we have an HTTP handler, terminate TLS and serve the request
	if m.httpHandler != nil {
		tlsConn := tls.Server(c, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return
		}

		// Serve HTTP request over the TLS connection
		m.serveHTTP(tlsConn)
		return
	}

	// No HTTP handler, just do handshake and close
	_ = tls.Server(c, tlsCfg).Handshake()
	c.Close()
}

// serveHTTP handles an HTTP request over a TLS connection.
func (m *HTTPSMuxer) serveHTTP(conn net.Conn) {
	defer conn.Close()

	// Read HTTP requests from the connection
	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// Create a response writer
		rw := &responseWriter{
			conn:   conn,
			header: make(http.Header),
		}

		// Set TLS state on request
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			req.TLS = &state
		}

		// Mark as HTTPS
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		// Serve the request
		m.httpHandler.ServeHTTP(rw, req)

		// Flush the response
		if err := rw.finalize(); err != nil {
			return
		}

		// Check if we should keep the connection alive
		if req.Close || rw.closeAfterReply {
			return
		}
	}
}

// responseWriter implements http.ResponseWriter for raw connections.
type responseWriter struct {
	conn            net.Conn
	header          http.Header
	wroteHeader     bool
	statusCode      int
	closeAfterReply bool
	buf             []byte
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	w.buf = append(w.buf, data...)
	return len(data), nil
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode
}

func (w *responseWriter) finalize() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Build response
	resp := &http.Response{
		StatusCode:    w.statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.header,
		ContentLength: int64(len(w.buf)),
	}

	// Check Connection header
	if w.header.Get("Connection") == "close" {
		w.closeAfterReply = true
	}

	// Write response header
	if err := resp.Write(w.conn); err != nil {
		return err
	}

	// Write body
	if len(w.buf) > 0 {
		if _, err := w.conn.Write(w.buf); err != nil {
			return err
		}
	}

	return nil
}

func GetHTTPSHostname(c net.Conn) (_ net.Conn, _ map[string]string, err error) {
	reqInfoMap := make(map[string]string, 0)
	sc, rd := libnet.NewSharedConn(c)

	clientHello, err := readClientHello(rd)
	if err != nil {
		return nil, reqInfoMap, err
	}

	reqInfoMap["Host"] = clientHello.ServerName
	reqInfoMap["Scheme"] = "https"
	return sc, reqInfoMap, nil
}

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	// Note that Handshake always fails because the readOnlyConn is not a real connection.
	// As long as the Client Hello is successfully read, the failure should only happen after GetConfigForClient is called,
	// so we only care about the error if hello was never set.
	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = &tls.ClientHelloInfo{}
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}
	return hello, nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(_ []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(_ time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(_ time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(_ time.Time) error { return nil }
