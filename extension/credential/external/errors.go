// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package external

import "fmt"

// AuthRequiredError is returned when the broker indicates the calling
// principal must (re-)authenticate before a token can be issued.
//
// Brokers signal this by responding to the token request with HTTP 401
// and a JSON body. The Code, Message, and AuthURL fields mirror those
// keys verbatim. AuthURL is optional: when present, the CLI surfaces it
// so the operator (or an upstream automation agent) can guide the user
// through the authentication flow without retrying blindly.
//
// Callers can inspect this error via errors.As. It is intentionally a
// dedicated type rather than a generic credential.BlockError because
// it represents a recoverable, user-actionable state — distinct from
// configuration errors (BlockError) and infrastructure errors (plain
// fmt.Errorf wrapping the underlying network failure).
type AuthRequiredError struct {
	// Code is the broker's "error" string (free-form, e.g. "auth_required").
	Code string
	// Message is the broker's human-readable explanation (optional).
	Message string
	// AuthURL is a URL the user should visit to complete authentication
	// (optional). Brokers that drive a web-based OAuth flow typically set
	// this; brokers backed by static keychains can leave it empty.
	AuthURL string
}

func (e *AuthRequiredError) Error() string {
	switch {
	case e.AuthURL != "" && e.Message != "":
		return fmt.Sprintf("token broker authentication required: %s (auth_url=%s)", e.Message, e.AuthURL)
	case e.AuthURL != "":
		return fmt.Sprintf("token broker authentication required (auth_url=%s)", e.AuthURL)
	case e.Message != "":
		return "token broker authentication required: " + e.Message
	default:
		return "token broker authentication required"
	}
}
