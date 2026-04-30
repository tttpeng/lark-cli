// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package envvars

const (
	CliAppID             = "LARKSUITE_CLI_APP_ID"
	CliAppSecret         = "LARKSUITE_CLI_APP_SECRET"
	CliBrand             = "LARKSUITE_CLI_BRAND"
	CliUserAccessToken   = "LARKSUITE_CLI_USER_ACCESS_TOKEN"
	CliTenantAccessToken = "LARKSUITE_CLI_TENANT_ACCESS_TOKEN"
	CliDefaultAs         = "LARKSUITE_CLI_DEFAULT_AS"
	CliStrictMode        = "LARKSUITE_CLI_STRICT_MODE"

	// Sidecar proxy (auth proxy mode)
	CliAuthProxy = "LARKSUITE_CLI_AUTH_PROXY" // sidecar HTTP address, e.g. "http://127.0.0.1:16384"
	CliProxyKey  = "LARKSUITE_CLI_PROXY_KEY"  // HMAC signing key shared with sidecar

	// External token broker (HTTP-based credential provider)
	CliTokenBrokerUATURL  = "LARKSUITE_CLI_TOKEN_BROKER_UAT_URL"  // GET endpoint that returns a user access token
	CliTokenBrokerTATURL  = "LARKSUITE_CLI_TOKEN_BROKER_TAT_URL"  // GET endpoint that returns a tenant access token
	CliTokenBrokerAuth    = "LARKSUITE_CLI_TOKEN_BROKER_AUTH"     // Authorization header value sent to the broker (verbatim, scheme-agnostic)
	CliTokenBrokerTimeout = "LARKSUITE_CLI_TOKEN_BROKER_TIMEOUT"  // request timeout, e.g. "5s" (default 5s)

	// Content safety scanning mode
	CliContentSafetyMode = "LARKSUITE_CLI_CONTENT_SAFETY_MODE"
)
