// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

// Package external provides a credential provider that fetches user
// and tenant access tokens from an HTTP-based token broker at runtime.
//
// # Use cases
//
//   - CI hosts shared by multiple engineers, where each engineer's
//     Feishu access tokens live in a central rotation service.
//   - Multi-user development VMs / containers where every shell
//     session must use its own caller-scoped token.
//   - Per-process automation platforms (agent runners, task workers)
//     that mint a short-lived token on each subprocess spawn.
//   - Internal vault / STS systems that hold Lark refresh tokens
//     centrally and produce access tokens on demand.
//
// # Activation
//
// Opt-in via either or both of:
//
//	LARKSUITE_CLI_TOKEN_BROKER_UAT_URL  # for user access tokens
//	LARKSUITE_CLI_TOKEN_BROKER_TAT_URL  # for tenant access tokens
//
// When neither is set, the provider returns nil from both ResolveAccount
// and ResolveToken, ceding to other providers in the chain (env,
// keychain, sidecar). The CLI's default behavior is unchanged for users
// who do not configure a broker.
//
// # Wire protocol
//
// CLI → broker:
//
//	GET <url>
//	Authorization: <verbatim value of LARKSUITE_CLI_TOKEN_BROKER_AUTH, optional>
//	Accept: application/json
//
// broker → CLI (HTTP 200, success):
//
//	{"access_token": "u-...", "expires_in": 7200}
//
// broker → CLI (HTTP 401, authentication required):
//
//	{"error": "auth_required", "message": "...", "auth_url": "https://..."}
//
// All other status codes are reported as broker errors. The auth header
// value is opaque to the CLI: brokers may use Bearer JWTs, Basic, or
// any custom scheme to authenticate the caller. The broker — not the
// CLI — defines what "the caller" means for each integration (a Linux
// user, an OS process, a logical principal id, etc.).
//
// # Security
//
// Tokens fetched by this provider enter the lark-cli process memory
// for the lifetime of the call. The provider is designed for
// environments where the CLI process itself is trusted (e.g. an
// internal agent runner under platform control).
//
// If your threat model requires that real tokens never enter the
// lark-cli process at all, use sidecar mode (-tags authsidecar)
// instead — sidecar provides transport-layer credential injection
// at the cost of an additional same-host server process and HMAC
// protocol overhead.
//
// Recommended hardening:
//
//   - Issue short-TTL tokens from the broker so leakage windows
//     are bounded.
//   - Authenticate callers via short-lived JWTs (set in
//     LARKSUITE_CLI_TOKEN_BROKER_AUTH) rather than long-lived
//     shared secrets.
//   - Restrict broker network exposure (loopback, unix socket,
//     private VPC) appropriate to your deployment.
//   - On Linux, consider ptrace_scope=2 and disabled core dumps
//     for the CLI process when running on shared hosts.
package external

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/larksuite/cli/extension/credential"
	"github.com/larksuite/cli/internal/envvars"
)

// Provider implements credential.Provider by delegating token issuance
// to an external HTTP broker.
type Provider struct {
	client *http.Client
}

func newProvider() *Provider {
	return &Provider{client: newHTTPClient()}
}

// Name implements credential.Provider.
func (p *Provider) Name() string { return "external" }

// Priority implements the optional priority hook recognized by
// credential.Register. Lower values are consulted first.
//
// The provider sits between sidecar (0) and env (default 10) so that:
//
//   - sidecar mode (build-tag-gated, when present) still wins, since
//     sidecar's stronger threat model should always be honored when
//     deliberately enabled;
//   - explicit access tokens injected via LARKSUITE_CLI_USER_ACCESS_TOKEN
//     (env provider) still override the broker, allowing local testing
//     and breakglass access without reconfiguring the broker.
func (p *Provider) Priority() int { return 5 }

// ResolveAccount declares the broker-backed account context.
//
// Returns nil, nil when the provider is not activated. Returns a
// BlockError when the configuration is partial (e.g. broker URL set
// but APP_ID missing, or strict-mode invalid) so the chain stops
// rather than silently falling through to a less-suitable provider.
func (p *Provider) ResolveAccount(_ context.Context) (*credential.Account, error) {
	if !p.activated() {
		return nil, nil
	}

	appID := os.Getenv(envvars.CliAppID)
	if appID == "" {
		return nil, &credential.BlockError{
			Provider: p.Name(),
			Reason: fmt.Sprintf("token broker URL is set (%s/%s) but %s is missing",
				envvars.CliTokenBrokerUATURL,
				envvars.CliTokenBrokerTATURL,
				envvars.CliAppID),
		}
	}

	brand := credential.Brand(os.Getenv(envvars.CliBrand))
	if brand == "" {
		brand = credential.BrandFeishu
	}

	acct := &credential.Account{
		AppID:     appID,
		AppSecret: credential.NoAppSecret,
		Brand:     brand,
	}

	if err := applyDefaultAs(acct); err != nil {
		return nil, err
	}
	if err := applySupportedIdentities(acct, p.declareIdentities()); err != nil {
		return nil, err
	}
	return acct, nil
}

// ResolveToken fetches the requested token type from the configured
// broker URL. Returns nil, nil when no URL is configured for the
// requested type — this allows partial deployments (e.g. UAT via
// broker + TAT via env) to work as expected.
func (p *Provider) ResolveToken(ctx context.Context, req credential.TokenSpec) (*credential.Token, error) {
	url := p.urlFor(req.Type)
	if url == "" {
		return nil, nil
	}
	return fetchToken(ctx, p.client, url)
}

// activated reports whether at least one broker URL is configured.
func (p *Provider) activated() bool {
	return os.Getenv(envvars.CliTokenBrokerUATURL) != "" ||
		os.Getenv(envvars.CliTokenBrokerTATURL) != ""
}

// declareIdentities derives the inferred SupportedIdentities from
// configured broker URLs. STRICT_MODE — when set — overrides this in
// applySupportedIdentities; when unset, this declaration becomes the
// effective policy, mirroring env provider behavior.
func (p *Provider) declareIdentities() credential.IdentitySupport {
	var s credential.IdentitySupport
	if os.Getenv(envvars.CliTokenBrokerUATURL) != "" {
		s |= credential.SupportsUser
	}
	if os.Getenv(envvars.CliTokenBrokerTATURL) != "" {
		s |= credential.SupportsBot
	}
	return s
}

func (p *Provider) urlFor(t credential.TokenType) string {
	switch t {
	case credential.TokenTypeUAT:
		return os.Getenv(envvars.CliTokenBrokerUATURL)
	case credential.TokenTypeTAT:
		return os.Getenv(envvars.CliTokenBrokerTATURL)
	default:
		return ""
	}
}

// applyDefaultAs reads CliDefaultAs into the account, returning a
// BlockError on invalid values. Semantics match env / sidecar providers.
func applyDefaultAs(acct *credential.Account) error {
	switch id := credential.Identity(os.Getenv(envvars.CliDefaultAs)); id {
	case "", credential.IdentityAuto:
		acct.DefaultAs = id
	case credential.IdentityUser, credential.IdentityBot:
		acct.DefaultAs = id
	default:
		return &credential.BlockError{
			Provider: "external",
			Reason: fmt.Sprintf("invalid %s %q (want user, bot, or auto)",
				envvars.CliDefaultAs, id),
		}
	}
	return nil
}

// applySupportedIdentities applies STRICT_MODE if set; otherwise uses
// the inferred default. STRICT_MODE always takes precedence to match
// env / sidecar provider policy.
func applySupportedIdentities(acct *credential.Account, inferred credential.IdentitySupport) error {
	switch strictMode := os.Getenv(envvars.CliStrictMode); strictMode {
	case "bot":
		acct.SupportedIdentities = credential.SupportsBot
	case "user":
		acct.SupportedIdentities = credential.SupportsUser
	case "off":
		acct.SupportedIdentities = credential.SupportsAll
	case "":
		acct.SupportedIdentities = inferred
	default:
		return &credential.BlockError{
			Provider: "external",
			Reason: fmt.Sprintf("invalid %s %q (want bot, user, or off)",
				envvars.CliStrictMode, strictMode),
		}
	}
	return nil
}

func init() {
	credential.Register(newProvider())
}
