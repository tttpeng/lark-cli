// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package external

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/larksuite/cli/extension/credential"
	"github.com/larksuite/cli/internal/envvars"
)

// defaultTimeout is the per-request timeout when CliTokenBrokerTimeout
// is unset or invalid. Five seconds is generous for a same-host or
// same-VPC broker but short enough that a wedged broker fails fast.
const defaultTimeout = 5 * time.Second

// maxResponseBytes caps the broker response body to defend against a
// misbehaving or hostile broker that returns an unbounded stream.
// Lark access tokens are bounded in length (a few KB at most); 64 KB
// leaves ample headroom for protocol metadata.
const maxResponseBytes = 64 * 1024

// brokerResponse is the wire-level JSON contract the CLI expects from
// a token broker. Both the success and error variants share this
// struct; unused fields are zero-valued in each case.
//
// Successful response (HTTP 200):
//
//	{"access_token": "u-xxx", "expires_in": 7200}
//
// Authentication required (HTTP 401):
//
//	{"error": "auth_required", "message": "...", "auth_url": "https://..."}
//
// Any other HTTP status is treated as a broker / network error and
// reported verbatim — the CLI does not assume a uniform error envelope
// across status codes, since brokers may delegate non-401 responses to
// upstream proxies / load balancers.
type brokerResponse struct {
	// Success fields (HTTP 200)
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"` // currently advisory; not used for caching in v1

	// Error fields (HTTP 401)
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	AuthURL string `json:"auth_url,omitempty"`
}

// fetchToken issues a single GET request to url and decodes the
// broker response according to the wire protocol documented above.
//
// The Authorization header — if CliTokenBrokerAuth is set — is passed
// through verbatim. The CLI does not interpret its scheme; brokers may
// use Bearer, Basic, mTLS-with-proxy, or a custom scheme to authenticate
// the calling principal. This separation of concerns is intentional:
// the CLI's responsibility ends at "deliver the operator's claim to
// the broker"; the broker decides what claim to require and how to
// validate it.
func fetchToken(ctx context.Context, client *http.Client, brokerURL string) (*credential.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, brokerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("external: build broker request: %w", err)
	}
	if auth := os.Getenv(envvars.CliTokenBrokerAuth); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Redact query string in the embedded URL of net/url.Error so the
		// principal/session/jwt commonly carried there is never echoed
		// into stderr or logs. Without this, the caller's auth context
		// can leak from a connection-refused message.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			uerr.URL = redactURL(uerr.URL)
		}
		return nil, fmt.Errorf("external: token broker unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("external: read broker response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var br brokerResponse
		if err := json.Unmarshal(body, &br); err != nil {
			return nil, fmt.Errorf("external: malformed broker response (200): %w", err)
		}
		if br.AccessToken == "" {
			return nil, fmt.Errorf("external: broker returned 200 but access_token is empty")
		}
		return &credential.Token{Value: br.AccessToken, Source: "external:" + redactURL(brokerURL)}, nil

	case http.StatusUnauthorized:
		var br brokerResponse
		// Best-effort decode: tolerate non-JSON 401 bodies (proxies, gateways,
		// brokers that return plain text). The user still gets an
		// AuthRequiredError; only the structured fields are missing.
		_ = json.Unmarshal(body, &br)
		return nil, &AuthRequiredError{
			Code:    br.Error,
			Message: br.Message,
			AuthURL: br.AuthURL,
		}

	default:
		return nil, fmt.Errorf("external: broker returned status %d", resp.StatusCode)
	}
}

// newHTTPClient builds the broker client honoring CliTokenBrokerTimeout.
// Accepts both a bare integer ("5", treated as seconds) and any value
// time.ParseDuration accepts ("5s", "1500ms"). Invalid values fall back
// to defaultTimeout silently — this is a power-user knob and we'd rather
// the CLI start than refuse on a typo.
func newHTTPClient() *http.Client {
	timeout := defaultTimeout
	if v := os.Getenv(envvars.CliTokenBrokerTimeout); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			timeout = d
		} else if d, err := time.ParseDuration(v + "s"); err == nil && d > 0 {
			timeout = d
		}
	}
	return &http.Client{Timeout: timeout}
}

// redactURL strips the query string from a broker URL before embedding
// it in error messages or Token.Source. Many integrators encode the
// caller principal (user_id, session token, etc.) in the query string;
// echoing it into stderr / logs would defeat the AUTH header's purpose.
//
// The path is preserved because routing prefixes ("/token/uat") are
// useful for debugging and don't typically encode secrets.
func redactURL(url string) string {
	if i := strings.IndexByte(url, '?'); i >= 0 {
		return url[:i] + "?<redacted>"
	}
	return url
}
