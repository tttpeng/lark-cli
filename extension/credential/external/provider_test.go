// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package external

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/larksuite/cli/extension/credential"
	"github.com/larksuite/cli/internal/envvars"
)

// ─── ResolveAccount ──────────────────────────────────────────────

func TestResolveAccount_NotActivated(t *testing.T) {
	// No broker URL env vars set: provider must skip silently.
	t.Setenv(envvars.CliTokenBrokerUATURL, "")
	t.Setenv(envvars.CliTokenBrokerTATURL, "")
	t.Setenv(envvars.CliAppID, "cli_x")

	p := newProvider()
	acct, err := p.ResolveAccount(context.Background())
	if err != nil || acct != nil {
		t.Fatalf("expected (nil, nil) when not activated, got (%+v, %v)", acct, err)
	}
}

func TestResolveAccount_Activated_Success(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliAppID, "cli_x")
	t.Setenv(envvars.CliBrand, "")        // default to feishu
	t.Setenv(envvars.CliStrictMode, "")   // infer from URLs
	t.Setenv(envvars.CliDefaultAs, "")

	p := newProvider()
	acct, err := p.ResolveAccount(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acct == nil {
		t.Fatal("expected non-nil account")
	}
	if acct.AppID != "cli_x" {
		t.Errorf("AppID = %q, want cli_x", acct.AppID)
	}
	if acct.AppSecret != credential.NoAppSecret {
		t.Errorf("AppSecret = %q, want NoAppSecret", acct.AppSecret)
	}
	if acct.Brand != credential.BrandFeishu {
		t.Errorf("Brand = %q, want feishu (default)", acct.Brand)
	}
	if !acct.SupportedIdentities.UserOnly() {
		t.Errorf("SupportedIdentities = %v, want UserOnly when only UAT URL is set", acct.SupportedIdentities)
	}
}

func TestResolveAccount_BothURLs_SupportsAll(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliTokenBrokerTATURL, "http://broker/tat")
	t.Setenv(envvars.CliAppID, "cli_x")
	t.Setenv(envvars.CliStrictMode, "")

	acct, err := newProvider().ResolveAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if acct.SupportedIdentities != credential.SupportsAll {
		t.Errorf("SupportedIdentities = %v, want SupportsAll", acct.SupportedIdentities)
	}
}

func TestResolveAccount_MissingAppID_Blocks(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliAppID, "")

	acct, err := newProvider().ResolveAccount(context.Background())
	if acct != nil {
		t.Error("expected nil account on missing APP_ID")
	}
	var be *credential.BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected BlockError, got %T: %v", err, err)
	}
	if !strings.Contains(be.Reason, envvars.CliAppID) {
		t.Errorf("Reason should mention %s, got %q", envvars.CliAppID, be.Reason)
	}
}

func TestResolveAccount_StrictModeOverridesInferred(t *testing.T) {
	// Both URLs configured (would infer SupportsAll), but STRICT_MODE=user
	// must clamp to UserOnly to match env/sidecar provider policy.
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliTokenBrokerTATURL, "http://broker/tat")
	t.Setenv(envvars.CliAppID, "cli_x")
	t.Setenv(envvars.CliStrictMode, "user")

	acct, err := newProvider().ResolveAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !acct.SupportedIdentities.UserOnly() {
		t.Errorf("STRICT_MODE=user should clamp to UserOnly, got %v", acct.SupportedIdentities)
	}
}

func TestResolveAccount_StrictModeInvalid_Blocks(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliAppID, "cli_x")
	t.Setenv(envvars.CliStrictMode, "garbage")

	_, err := newProvider().ResolveAccount(context.Background())
	var be *credential.BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected BlockError on invalid STRICT_MODE, got %v", err)
	}
}

func TestResolveAccount_DefaultAsInvalid_Blocks(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliAppID, "cli_x")
	t.Setenv(envvars.CliDefaultAs, "service-account") // not a valid Identity

	_, err := newProvider().ResolveAccount(context.Background())
	var be *credential.BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected BlockError on invalid DEFAULT_AS, got %v", err)
	}
}

// ─── ResolveToken ────────────────────────────────────────────────

func TestResolveToken_NotConfigured_Skips(t *testing.T) {
	// UAT URL set but caller asks for TAT — must skip (return nil, nil)
	// so the chain falls through to env / keychain.
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://broker/uat")
	t.Setenv(envvars.CliTokenBrokerTATURL, "")

	tok, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeTAT, AppID: "cli_x"})
	if err != nil || tok != nil {
		t.Fatalf("expected (nil, nil) when TAT URL unset, got (%+v, %v)", tok, err)
	}
}

func TestResolveToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"u-12345","expires_in":7200}`)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	tok, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == nil || tok.Value != "u-12345" {
		t.Errorf("token value = %+v, want u-12345", tok)
	}
	if !strings.HasPrefix(tok.Source, "external:") {
		t.Errorf("token source should start with 'external:', got %q", tok.Source)
	}
}

func TestResolveToken_AuthHeaderPassthrough(t *testing.T) {
	// The CLI must pass through CliTokenBrokerAuth as the Authorization
	// header verbatim — this is the channel through which brokers
	// authenticate the calling principal. The CLI must not interpret
	// or rewrite it.
	const wantAuth = "Bearer eyJraWQ.payload.sig"

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"access_token":"u-ok"}`)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)
	t.Setenv(envvars.CliTokenBrokerAuth, wantAuth)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != wantAuth {
		t.Errorf("broker received Authorization=%q, want %q", gotAuth, wantAuth)
	}
}

func TestResolveToken_Unauthorized_ReturnsAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"auth_required","message":"please log in","auth_url":"https://accounts.feishu.cn/oauth?state=42"}`)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})

	var are *AuthRequiredError
	if !errors.As(err, &are) {
		t.Fatalf("expected AuthRequiredError, got %T: %v", err, err)
	}
	if are.Code != "auth_required" || are.AuthURL == "" || !strings.Contains(are.Error(), "auth_url=") {
		t.Errorf("AuthRequiredError fields not populated correctly: %+v", are)
	}
}

func TestResolveToken_Unauthorized_NonJSONBody_StillAuthRequired(t *testing.T) {
	// Tolerate plain-text 401 from gateways / proxies in front of broker.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorized")
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})

	var are *AuthRequiredError
	if !errors.As(err, &are) {
		t.Fatalf("expected AuthRequiredError on plain-text 401, got %T: %v", err, err)
	}
}

func TestResolveToken_ServerError_ReturnsBrokerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	var are *AuthRequiredError
	if errors.As(err, &are) {
		t.Errorf("500 must not be classified as AuthRequiredError")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500: %v", err)
	}
}

func TestResolveToken_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json at all")
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed-response error, got: %v", err)
	}
}

func TestResolveToken_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":""}`)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-access_token error, got: %v", err)
	}
}

func TestResolveToken_OversizedBody_Truncated(t *testing.T) {
	// Broker returns a body that vastly exceeds maxResponseBytes. The
	// client must truncate to avoid unbounded memory; the truncated
	// response will fail JSON parse, which is acceptable — the goal is
	// to bound resource usage, not to recover gracefully.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 1 MB of garbage prefixed with valid JSON start
		w.Write([]byte(`{"access_token":"`))
		blob := make([]byte, maxResponseBytes*2)
		for i := range blob {
			blob[i] = 'x'
		}
		w.Write(blob)
	}))
	defer srv.Close()

	t.Setenv(envvars.CliTokenBrokerUATURL, srv.URL)

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil {
		t.Error("expected truncation to cause parse error or empty token, got nil")
	}
}

func TestResolveToken_BrokerUnreachable(t *testing.T) {
	// Use an address that's guaranteed not to accept connections.
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://127.0.0.1:1/uat")
	t.Setenv(envvars.CliTokenBrokerTimeout, "200ms")

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("expected 'unreachable' error, got: %v", err)
	}
}

func TestResolveToken_RedactsQueryStringInError(t *testing.T) {
	// Many integrators encode caller principal in the query string
	// (e.g. ?session_jwt=xyz). The CLI must not echo this into error
	// strings or token sources.
	const principal = "session_jwt=SECRET_PRINCIPAL"
	t.Setenv(envvars.CliTokenBrokerUATURL, "http://127.0.0.1:1/uat?"+principal)
	t.Setenv(envvars.CliTokenBrokerTimeout, "200ms")

	_, err := newProvider().ResolveToken(context.Background(),
		credential.TokenSpec{Type: credential.TokenTypeUAT})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRET_PRINCIPAL") {
		t.Errorf("error message leaked secret query string: %v", err)
	}
}

// ─── HTTP client construction ───────────────────────────────────

func TestNewHTTPClient_DefaultTimeout(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerTimeout, "")
	c := newHTTPClient()
	if c.Timeout != defaultTimeout {
		t.Errorf("default timeout = %v, want %v", c.Timeout, defaultTimeout)
	}
}

func TestNewHTTPClient_CustomDuration(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerTimeout, "750ms")
	c := newHTTPClient()
	if c.Timeout != 750*time.Millisecond {
		t.Errorf("timeout = %v, want 750ms", c.Timeout)
	}
}

func TestNewHTTPClient_BareInteger(t *testing.T) {
	// "3" should be interpreted as 3 seconds, mirroring how operators
	// commonly write timeout values.
	t.Setenv(envvars.CliTokenBrokerTimeout, "3")
	c := newHTTPClient()
	if c.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", c.Timeout)
	}
}

func TestNewHTTPClient_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv(envvars.CliTokenBrokerTimeout, "garbage")
	c := newHTTPClient()
	if c.Timeout != defaultTimeout {
		t.Errorf("invalid timeout should fall back to default, got %v", c.Timeout)
	}
}

// ─── Provider metadata ──────────────────────────────────────────

func TestProvider_NameAndPriority(t *testing.T) {
	p := newProvider()
	if p.Name() != "external" {
		t.Errorf("Name() = %q, want external", p.Name())
	}
	if p.Priority() != 5 {
		t.Errorf("Priority() = %d, want 5 (between sidecar=0 and env=10)", p.Priority())
	}
}
