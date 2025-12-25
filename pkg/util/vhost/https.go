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
	"crypto/tls"
	"io"
	"net"
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

type HTTPSMuxer struct {
	*Muxer
	acmeProvider ACMEProvider
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
func (m *HTTPSMuxer) vhostFailedWithACME(c net.Conn) {
	tlsCfg := &tls.Config{}
	if m.acmeProvider != nil {
		tlsCfg.GetCertificate = m.acmeProvider.GetCertificate()
	}
	// Try to complete handshake (will fail but provides proper TLS alert)
	_ = tls.Server(c, tlsCfg).Handshake()
	c.Close()
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
