// Copyright 2023 The frp Authors
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

package validation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/policy/featuregate"
	"github.com/fatedier/frp/pkg/policy/security"
)

func (v *ConfigValidator) ValidateServerConfig(c *v1.ServerConfig) (Warning, error) {
	var (
		warnings Warning
		errs     error
	)
	if !slices.Contains(SupportedAuthMethods, c.Auth.Method) {
		errs = AppendError(errs, fmt.Errorf("invalid auth method, optional values are %v", SupportedAuthMethods))
	}
	if !lo.Every(SupportedAuthAdditionalScopes, c.Auth.AdditionalScopes) {
		errs = AppendError(errs, fmt.Errorf("invalid auth additional scopes, optional values are %v", SupportedAuthAdditionalScopes))
	}

	// Validate token/tokenSource mutual exclusivity
	if c.Auth.Token != "" && c.Auth.TokenSource != nil {
		errs = AppendError(errs, fmt.Errorf("cannot specify both auth.token and auth.tokenSource"))
	}

	// Validate tokenSource if specified
	if c.Auth.TokenSource != nil {
		if c.Auth.TokenSource.Type == "exec" {
			if err := v.ValidateUnsafeFeature(security.TokenSourceExec); err != nil {
				errs = AppendError(errs, err)
			}
		}
		if err := c.Auth.TokenSource.Validate(); err != nil {
			errs = AppendError(errs, fmt.Errorf("invalid auth.tokenSource: %v", err))
		}
	}

	if err := validateLogConfig(&c.Log); err != nil {
		errs = AppendError(errs, err)
	}

	if err := validateWebServerConfig(&c.WebServer); err != nil {
		errs = AppendError(errs, err)
	}

	errs = AppendError(errs, ValidatePort(c.BindPort, "bindPort"))
	errs = AppendError(errs, ValidatePort(c.KCPBindPort, "kcpBindPort"))
	errs = AppendError(errs, ValidatePort(c.QUICBindPort, "quicBindPort"))
	errs = AppendError(errs, ValidatePort(c.VhostHTTPPort, "vhostHTTPPort"))
	errs = AppendError(errs, ValidatePort(c.VhostHTTPSPort, "vhostHTTPSPort"))
	errs = AppendError(errs, ValidatePort(c.TCPMuxHTTPConnectPort, "tcpMuxHTTPConnectPort"))

	for _, p := range c.HTTPPlugins {
		if !lo.Every(SupportedHTTPPluginOps, p.Ops) {
			errs = AppendError(errs, fmt.Errorf("invalid http plugin ops, optional values are %v", SupportedHTTPPluginOps))
		}
	}

	if err := validateACMEConfig(&c.ACME); err != nil {
		errs = AppendError(errs, err)
	}

	return warnings, errs
}

func validateACMEConfig(c *v1.ACMEConfig) error {
	if !c.Enable {
		return nil
	}

	var errs error

	// Check feature gate is enabled
	if !featuregate.Enabled(featuregate.ACME) {
		errs = AppendError(errs, fmt.Errorf("acme is enabled but ACME feature gate is not enabled; set featureGates.ACME=true"))
	}

	// Email is required
	if c.Email == "" {
		errs = AppendError(errs, fmt.Errorf("acme.email is required when ACME is enabled"))
	}

	// AcceptTOS is required
	if !c.AcceptTOS {
		errs = AppendError(errs, fmt.Errorf("acme.acceptTOS must be true to use Let's Encrypt"))
	}

	// If dashboard ACME is enabled, domains are required
	if lo.FromPtr(c.EnableForDashboard) && len(c.DashboardDomains) == 0 {
		errs = AppendError(errs, fmt.Errorf("acme.dashboardDomains is required when acme.enableForDashboard is true"))
	}

	// Validate no wildcard domains (HTTP-01 doesn't support wildcards)
	for _, d := range c.DashboardDomains {
		if strings.HasPrefix(d, "*") || strings.Contains(d, "*") {
			errs = AppendError(errs, fmt.Errorf("wildcard domain %q is not supported with HTTP-01 challenge; use DNS-01 for wildcards", d))
		}
	}

	return errs
}
