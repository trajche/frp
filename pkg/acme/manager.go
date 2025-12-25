// Copyright 2025 The frp Authors
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

package acme

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/fatedier/frp/pkg/util/log"
)

// Manager handles ACME certificate provisioning and renewal.
type Manager struct {
	cfg    *Config
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer

	// Domain tracking
	domains   map[string]int // domain -> reference count
	domainsMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager creates a new ACME manager with the given configuration.
func NewManager(cfg *Config) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Configure certmagic storage
	storage := &certmagic.FileStorage{Path: cfg.StoragePath}

	// Create certmagic config
	magic := certmagic.NewDefault()
	magic.Storage = storage

	// Configure the ACME issuer
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:     cfg.CAEndpoint,
		Email:  cfg.Email,
		Agreed: true,
	})
	magic.Issuers = []certmagic.Issuer{issuer}

	// Enable on-demand TLS for dynamic certificate provisioning
	magic.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			// Certificate decisions are made via registered domains
			return nil
		},
	}

	m := &Manager{
		cfg:     cfg,
		magic:   magic,
		issuer:  issuer,
		domains: make(map[string]int),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Pre-register dashboard domains if enabled
	if cfg.EnableForDashboard {
		for _, domain := range cfg.DashboardDomains {
			m.RegisterDomain(domain)
		}
	}

	return m, nil
}

// Start begins the ACME manager's background operations.
func (m *Manager) Start(ctx context.Context) error {
	log.Infof("ACME manager started, storage: %s, CA: %s", m.cfg.StoragePath, m.cfg.CAEndpoint)

	// Certmagic handles renewal automatically in the background
	// We just need to keep the context alive
	<-ctx.Done()
	return ctx.Err()
}

// Stop gracefully shuts down the ACME manager.
func (m *Manager) Stop() {
	m.cancel()
	log.Infof("ACME manager stopped")
}

// RegisterDomain adds a domain for certificate management.
// Multiple registrations of the same domain are reference-counted.
func (m *Manager) RegisterDomain(domain string) {
	m.domainsMu.Lock()
	defer m.domainsMu.Unlock()

	m.domains[domain]++
	if m.domains[domain] == 1 {
		log.Infof("ACME: registered domain %s for certificate management", domain)
	}
}

// UnregisterDomain removes a domain from certificate management.
// The domain is only removed when the reference count reaches zero.
func (m *Manager) UnregisterDomain(domain string) {
	m.domainsMu.Lock()
	defer m.domainsMu.Unlock()

	if count, ok := m.domains[domain]; ok {
		m.domains[domain] = count - 1
		if m.domains[domain] <= 0 {
			delete(m.domains, domain)
			log.Infof("ACME: unregistered domain %s from certificate management", domain)
		}
	}
}

// IsDomainRegistered checks if a domain is registered for certificate management.
func (m *Manager) IsDomainRegistered(domain string) bool {
	m.domainsMu.RLock()
	defer m.domainsMu.RUnlock()
	return m.domains[domain] > 0
}

// GetDomains returns a list of all registered domains.
func (m *Manager) GetDomains() []string {
	m.domainsMu.RLock()
	defer m.domainsMu.RUnlock()

	domains := make([]string, 0, len(m.domains))
	for domain := range m.domains {
		domains = append(domains, domain)
	}
	return domains
}

// GetCertificate returns a function suitable for use as tls.Config.GetCertificate.
// It obtains and renews certificates automatically for registered domains.
func (m *Manager) GetCertificate() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Check if domain is registered
		if !m.IsDomainRegistered(hello.ServerName) {
			log.Debugf("ACME: domain %s not registered, skipping certificate lookup", hello.ServerName)
			return nil, nil
		}

		// Use certmagic to get/obtain the certificate
		return m.magic.GetCertificate(hello)
	}
}

// GetTLSConfig returns a complete tls.Config for HTTPS listeners.
func (m *Manager) GetTLSConfig() *tls.Config {
	return m.magic.TLSConfig()
}

// HTTPChallengeHandler wraps an HTTP handler to handle ACME HTTP-01 challenges.
// Requests to /.well-known/acme-challenge/ are handled by certmagic,
// all other requests are passed to the fallback handler.
func (m *Manager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	return m.issuer.HTTPChallengeHandler(fallback)
}

// Config returns the ACME manager's configuration.
func (m *Manager) Config() *Config {
	return m.cfg
}
