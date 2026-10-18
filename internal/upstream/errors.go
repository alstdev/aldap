package upstream

import "errors"

// Sentinel errors, matched with errors.Is.
var (
	// ErrUnavailable reports that no upstream server could serve the request.
	ErrUnavailable = errors.New("upstream unavailable")
	// ErrAbsoluteFalse reports a filter that can never match; no query is sent.
	ErrAbsoluteFalse = errors.New("filter is absolute false")
	// ErrEmptyPassword reports a user bind without a password (anonymous).
	ErrEmptyPassword = errors.New("empty password")
	// ErrClosed reports use after Close.
	ErrClosed = errors.New("upstream closed")
	// ErrPoolExhausted reports that no pooled connection became free in time.
	ErrPoolExhausted = errors.New("connection pool exhausted")
	// ErrReferral reports a referral result (code 10); referrals are never followed.
	ErrReferral = errors.New("referral not followed")
	// ErrConnect wraps every failure to establish a usable connection
	// (dial, TLS, StartTLS, service bind); it counts against the server.
	ErrConnect = errors.New("connect failed")
)
