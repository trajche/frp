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
	"os"
	"path/filepath"

	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

const (
	// DefaultStoragePath is the default directory for storing ACME certificates and account data.
	DefaultStoragePath = ".frp/acme"

	// LetsEncryptProduction is the Let's Encrypt production ACME endpoint.
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"

	// LetsEncryptStaging is the Let's Encrypt staging ACME endpoint for testing.
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Config holds the ACME configuration used by the Manager.
type Config struct {
	// Email for ACME account registration.
	Email string
	// CAEndpoint is the ACME CA directory URL.
	CAEndpoint string
	// StoragePath is the directory for certificate and account storage.
	StoragePath string
	// EnableForVhost enables ACME for vhost HTTPS proxies.
	EnableForVhost bool
	// EnableForDashboard enables ACME for dashboard.
	EnableForDashboard bool
	// DashboardDomains are domains for the dashboard certificate.
	DashboardDomains []string
}

// ConfigFromServerConfig creates an ACME Config from the server's ACMEConfig.
func ConfigFromServerConfig(c *v1.ACMEConfig) *Config {
	storagePath := c.StoragePath
	if storagePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		storagePath = filepath.Join(home, DefaultStoragePath)
	}

	caEndpoint := c.CAEndpoint
	if caEndpoint == "" {
		caEndpoint = LetsEncryptProduction
	}

	return &Config{
		Email:              c.Email,
		CAEndpoint:         caEndpoint,
		StoragePath:        storagePath,
		EnableForVhost:     lo.FromPtr(c.EnableForVhost),
		EnableForDashboard: lo.FromPtr(c.EnableForDashboard),
		DashboardDomains:   c.DashboardDomains,
	}
}
