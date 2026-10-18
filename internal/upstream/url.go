package upstream

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ServerURL is a parsed upstream server address.
type ServerURL struct {
	// Raw is the URL as configured.
	Raw string
	// Scheme is "ldap" or "ldaps".
	Scheme string
	// Host is the host name or IP without port.
	Host string
	// Port is the explicit or default port (389/636).
	Port string
}

// ParseServerURL parses ldap://host[:port] or ldaps://host[:port].
func ParseServerURL(s string) (ServerURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return ServerURL{}, fmt.Errorf("server url %q: %w", s, err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return ServerURL{}, fmt.Errorf("server url %q: scheme must be ldap or ldaps", s)
	}
	if u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return ServerURL{}, fmt.Errorf("server url %q: must be scheme://host[:port]", s)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return ServerURL{}, fmt.Errorf("server url %q: missing host", s)
	}
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	return ServerURL{Raw: s, Scheme: u.Scheme, Host: host, Port: port}, nil
}

// Addr returns host:port for dialing.
func (s ServerURL) Addr() string { return net.JoinHostPort(s.Host, s.Port) }

// TLS reports whether the transport is ldaps.
func (s ServerURL) TLS() bool { return s.Scheme == "ldaps" }

// String returns the canonical URL (scheme://host:port).
func (s ServerURL) String() string {
	if strings.Contains(s.Host, ":") {
		return s.Scheme + "://[" + s.Host + "]:" + s.Port
	}
	return s.Scheme + "://" + s.Host + ":" + s.Port
}
