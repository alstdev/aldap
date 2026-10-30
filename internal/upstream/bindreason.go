package upstream

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Reason is the bind_fail reason (SPEC §6).
type Reason string

// Bind failure reasons.
const (
	ReasonNone            Reason = ""
	ReasonInvalidPassword Reason = "invalid_password"
	ReasonUnknownAccount  Reason = "unknown_account"
	ReasonDisabled        Reason = "disabled"
	ReasonLockedInAD      Reason = "locked_in_ad"
	ReasonExpired         Reason = "expired"
	ReasonMustChange      Reason = "must_change"
	ReasonAnonymous       Reason = "anonymous"
	ReasonUpstreamError   Reason = "upstream_error"
)

// adDataRe extracts the data code of an AcceptSecurityContext diagnostic.
var adDataRe = regexp.MustCompile(`AcceptSecurityContext error, data ([0-9A-Fa-f]+)`)

// adData maps AD data codes to reasons (SPEC §4.3). 530 (logon hours) and
// 531 (workstation restriction) are reported as disabled: the account cannot
// log in now and the client is told invalidCredentials either way.
var adData = map[string]Reason{
	"525": ReasonUnknownAccount,
	"52e": ReasonInvalidPassword,
	"530": ReasonDisabled,
	"531": ReasonDisabled,
	"532": ReasonExpired,
	"533": ReasonDisabled,
	"701": ReasonExpired,
	"773": ReasonMustChange,
	"775": ReasonLockedInAD,
}

// BindError is a failed user bind: the client always gets invalidCredentials,
// the event carries Reason.
type BindError struct {
	Reason Reason
	// Data is the AD data code ("52e"), "" for non-AD servers.
	Data string
	Err  error
}

// Error never includes the password. A credential failure is reported by
// its reason (and AD data code) only; a directory failure (upstream_error:
// signing required, TLS required, server error) names the LDAP result so
// an operator sees why the directory refused, not a generic word.
func (e *BindError) Error() string {
	if e.Reason == ReasonUpstreamError && e.Err != nil {
		return fmt.Sprintf("bind failed: %s: %v", e.Reason, e.Err)
	}
	if e.Data != "" {
		return fmt.Sprintf("bind failed: %s (data %s)", e.Reason, e.Data)
	}
	return fmt.Sprintf("bind failed: %s", e.Reason)
}

// Unwrap returns the underlying LDAP error.
func (e *BindError) Unwrap() error { return e.Err }

// Level is the event level for the reason: locked_in_ad is medium (the
// attack reached the directory), everything else low.
func (e *BindError) Level() string {
	if e.Reason == ReasonLockedInAD {
		return "medium"
	}
	return "low"
}

// ClassifyBindError maps an error returned by a simple bind to a Reason.
// nil → ReasonNone; invalidCredentials → the AD data code, or
// invalid_password when there is none; anything else → upstream_error.
func ClassifyBindError(err error) (Reason, string) {
	if err == nil {
		return ReasonNone, ""
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return ReasonUpstreamError, ""
	}
	if m := adDataRe.FindStringSubmatch(err.Error()); m != nil {
		code := strings.ToLower(m[1])
		if r, ok := adData[code]; ok {
			return r, code
		}
		return ReasonInvalidPassword, code
	}
	return ReasonInvalidPassword, ""
}

// IsCredentialFailure reports whether err is a BindError (not a transport error).
func IsCredentialFailure(err error) bool {
	var be *BindError
	return errors.As(err, &be)
}
