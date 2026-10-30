package config

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/alstdev/aldap/internal/secret"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Issue is one validation finding, located by the dotted key path.
type Issue struct {
	Path string `json:"path"`
	Msg  string `json:"msg"`
}

// String renders "path: msg".
func (i Issue) String() string { return i.Path + ": " + i.Msg }

// Report collects validation errors and warnings. It is an error when it has errors.
type Report struct {
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

// OK reports whether there are no errors.
func (r *Report) OK() bool { return len(r.Errors) == 0 }

// Error joins the errors, one per line.
func (r *Report) Error() string {
	lines := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		lines = append(lines, e.String())
	}
	return strings.Join(lines, "\n")
}

func (r *Report) errorf(path, format string, args ...any) {
	r.Errors = append(r.Errors, Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (r *Report) warnf(path, format string, args ...any) {
	r.Warnings = append(r.Warnings, Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// Validator runs the offline checks of SPEC §3.5 with injectable accessors.
type Validator struct {
	// Secrets probes secret files; defaults to secret.Default.
	Secrets secret.Resolver
	// ReadFile reads certificate files; defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Now defaults to time.Now.
	Now func() time.Time
	// globalClientCA is [tls].client_ca while profiles are validated.
	globalClientCA string
	// StrictFiles turns unreadable secret and certificate files into errors.
	// Offline `aldap check` leaves it false because such files are often
	// mounted only at run time (/run/secrets); `aldap run` sets it.
	StrictFiles bool
	// ParseFilter checks LDAP filter syntax; defaults to the RFC 4515
	// parser of internal/ldapfilter.
	ParseFilter func(string) error
	// ParseDN checks DN syntax; defaults to the RFC 4514 parser of
	// internal/ldapfilter.
	ParseDN func(string) error
}

// Validate runs the default offline validator and returns the report as an
// error when it has errors.
func (c *Config) Validate() error {
	rep := Validator{}.Validate(c)
	if rep.OK() {
		return nil
	}
	return rep
}

// Validate runs every offline rule and returns the report.
func (v Validator) Validate(c *Config) *Report {
	v = v.withDefaults()
	v.globalClientCA = c.TLS.ClientCA
	rep := &Report{}
	c.Server.validate("server", rep)
	v.validateTLS("tls", &c.TLS, c.listenHosts(), rep)
	c.Ratelimit.validate("ratelimit", rep)
	c.Intrusion.validate("ids", rep)
	for _, name := range sortedKeys(c.Upstreams) {
		v.validateUpstream("upstream."+name, name, c.Upstreams[name], rep)
	}
	for _, name := range sortedKeys(c.Profiles) {
		v.validateProfile("profile."+name, name, c.Profiles[name], c, rep)
	}
	v.validateProfilesCross(c, rep)
	v.validateEvents("events", &c.Events, rep)
	v.validateNotify("notify", &c.Notify, rep)
	v.validateAPI("api", &c.API, rep)
	validatePathCollisions(c, rep)
	return rep
}

func (v Validator) withDefaults() Validator {
	if v.ReadFile == nil {
		v.ReadFile = os.ReadFile
	}
	if v.Now == nil {
		v.Now = time.Now
	}
	if v.ParseFilter == nil {
		v.ParseFilter = filterSyntax
	}
	if v.ParseDN == nil {
		v.ParseDN = dnSyntax
	}
	return v
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- helpers --------------------------------------------------------------

func oneOf(rep *Report, path, val string, allowed ...string) bool {
	if slices.Contains(allowed, val) {
		return true
	}
	rep.errorf(path, "%q is not one of %s", val, strings.Join(allowed, ", "))
	return false
}

func positive(rep *Report, path string, d Duration) {
	if d <= 0 {
		rep.errorf(path, "must be a positive duration, got %s", d)
	}
}

func atLeast(rep *Report, path string, n, minimum int) {
	if n < minimum {
		rep.errorf(path, "must be at least %d, got %d", minimum, n)
	}
}

// checkCIDRs validates an allow list. A /0 prefix is refused: it would exempt
// every address from the limits, locks or token restriction the list guards.
func checkCIDRs(rep *Report, path string, list []string) {
	for i, s := range list {
		p := fmt.Sprintf("%s[%d]", path, i)
		if pfx, err := netip.ParsePrefix(s); err == nil {
			if pfx.Bits() == 0 {
				rep.errorf(p, "%q matches every address; an allow list must name specific networks", s)
			}
			continue
		}
		if _, err := netip.ParseAddr(s); err == nil {
			continue
		}
		rep.errorf(p, "%q is not an IP address or CIDR", s)
	}
}

func checkListen(rep *Report, path, addr string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		rep.errorf(path, "%q is not host:port", addr)
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		rep.errorf(path, "%q has an invalid port", addr)
		return "", 0, false
	}
	return h, n, true
}

// checkSystemdName validates the name of "systemd:<name>": a systemd
// FileDescriptorName= is at most 255 printable ASCII characters without ':'
// (systemd.socket(5)).
func checkSystemdName(rep *Report, path, name string) {
	ok := name != "" && len(name) <= 255
	for _, r := range name {
		if r <= ' ' || r > '~' || r == ':' {
			ok = false
		}
	}
	if !ok {
		rep.errorf(path, "%q: the socket name must be 1-255 printable ASCII characters without ':' or spaces (FileDescriptorName=)", ListenSystemdPrefix+name)
	}
}

// validateProxyProtocol requires trusted_cidrs when the header is accepted:
// a header from anywhere would let every client choose its address.
func validateProxyProtocol(path string, pp *ProxyProtocol, rep *Report) {
	checkCIDRs(rep, path+".trusted_cidrs", pp.TrustedCIDRs)
	if !pp.Enabled {
		return
	}
	if len(pp.TrustedCIDRs) == 0 {
		rep.errorf(path+".trusted_cidrs", "required when enabled = true: the PROXY header is accepted only from these proxy addresses")
	}
	for i, c := range pp.TrustedCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Bits() == 0 {
			rep.errorf(fmt.Sprintf("%s.trusted_cidrs[%d]", path, i), "%q trusts every address: any client could choose its source address", c)
		}
	}
}

func isWildcardHost(h string) bool {
	return h == "" || h == "0.0.0.0" || h == "::" || h == "[::]"
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && a.IsLoopback()
}

// checkSecret validates a secret source: at most one form, inline warned,
// file probed. required demands that some form is set.
func (v Validator) checkSecret(rep *Report, path string, src secret.Source, required bool) {
	if err := src.Check(); err != nil {
		rep.errorf(path, "%v: use exactly one of %s, %s_file, %s_env", err, path, path, path)
		return
	}
	switch src.Kind() {
	case "":
		if required {
			rep.errorf(path, "required: set %s_file, %s_env or %s", path, path, path)
		}
	case "inline":
		if src.Inline.Reveal() == secret.Redacted {
			rep.errorf(path, "is the masked placeholder %q of a rendered configuration: give the secret or use %s_file / %s_env", secret.Redacted, path, path)
			return
		}
		rep.warnf(path, "inline secret; prefer %s_file or %s_env", path, path)
	case "file":
		warns, err := v.Secrets.Probe(src)
		for _, w := range warns {
			rep.warnf(path+"_file", "%s", w.Msg)
		}
		if err != nil {
			if v.StrictFiles {
				rep.errorf(path+"_file", "%v", err)
			} else {
				rep.warnf(path+"_file", "%v (verified again at start)", err)
			}
		}
	}
}

// filterSyntax parses s with the RFC 4515 parser and default limits.
func filterSyntax(s string) error {
	_, err := ldapfilter.Parse(s)
	return err
}

// dnSyntax parses s with the RFC 4514 parser.
func dnSyntax(s string) error {
	_, err := ldapfilter.ParseDN(s)
	return err
}

// ---- sections -------------------------------------------------------------

// Validate checks the section on its own.
func (s *Server) Validate() error { return sectionError(s.validate, "server") }

func (s *Server) validate(path string, rep *Report) {
	oneOf(rep, path+".log_level", s.LogLevel, "debug", "info", "warn", "error")
	oneOf(rep, path+".log_format", s.LogFormat, "text", "json")
	positive(rep, path+".shutdown_timeout", s.ShutdownTimeout)
	atLeast(rep, path+".max_connections", s.MaxConnections, 1)
	if s.IPCSocket == "" {
		rep.errorf(path+".ipc_socket", "required")
	}
}

// Validate checks the section on its own.
func (t *TLS) Validate() error {
	return sectionError(func(p string, r *Report) { Validator{}.withDefaults().validateTLS(p, t, nil, r) }, "tls")
}

func (v Validator) validateTLS(path string, t *TLS, listenHosts []string, rep *Report) {
	if oneOf(rep, path+".mode", t.Mode, "builtin-ca", "external") {
		switch t.Mode {
		case "builtin-ca":
			if t.CADir == "" {
				rep.errorf(path+".ca_dir", "required for mode = builtin-ca")
			}
		case "external":
			if t.Cert == "" || t.Key == "" {
				rep.errorf(path+".cert", "cert and key are required for mode = external")
			} else {
				v.checkCertFile(rep, path+".cert", t.Cert, t.ExpiryAlertBefore, listenHosts)
			}
		}
	}
	oneOf(rep, path+".key_type", t.KeyType, "ecdsa-p256", "rsa-2048")
	oneOf(rep, path+".min_version", t.MinVersion, "1.2", "1.3")
	if oneOf(rep, path+".client_auth", t.ClientAuth, "none", "request", "require") && t.ClientAuth != "none" && t.ClientCA == "" {
		rep.errorf(path+".client_ca", "required for client_auth = %s", t.ClientAuth)
	}
	positive(rep, path+".auto_renew_before", t.AutoRenewBefore)
	positive(rep, path+".expiry_alert_before", t.ExpiryAlertBefore)
}

func (v Validator) checkCertFile(rep *Report, path, file string, alertBefore Duration, listenHosts []string) {
	data, err := v.ReadFile(file)
	if err != nil {
		if v.StrictFiles {
			rep.errorf(path, "%v", err)
		} else {
			rep.warnf(path, "%v (verified again at start)", err)
		}
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		rep.errorf(path, "%s is not PEM", file)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		rep.errorf(path, "%s: %v", file, err)
		return
	}
	now := v.Now()
	switch {
	case now.After(cert.NotAfter):
		rep.errorf(path, "certificate expired on %s", cert.NotAfter.UTC().Format(time.RFC3339))
	case now.Add(alertBefore.D()).After(cert.NotAfter):
		rep.warnf(path, "certificate expires on %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, h := range listenHosts {
		if isWildcardHost(h) {
			continue
		}
		if err := cert.VerifyHostname(h); err != nil {
			rep.warnf(path, "certificate does not cover listen host %q", h)
		}
	}
}

// listenHosts returns the distinct non-wildcard hosts of every profile listen address.
func (c *Config) listenHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range c.Profiles {
		for _, addr := range p.Listen {
			if h, _, err := net.SplitHostPort(addr); err == nil && !isWildcardHost(h) && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Validate checks the section on its own.
func (r *Ratelimit) Validate() error { return sectionError(r.validate, "ratelimit") }

func (r *Ratelimit) validate(path string, rep *Report) {
	positive(rep, path+".negative_cache_ttl", r.NegativeCacheTTL)
	oneOf(rep, path+".lock_response", r.LockResponse, "invalidCredentials", "busy")
	checkCIDRs(rep, path+".allow_cidrs", r.AllowCIDRs)
	atLeast(rep, path+".ip.max_failures", r.IP.MaxFailures, 1)
	positive(rep, path+".ip.window", r.IP.Window)
	positive(rep, path+".ip.lock_duration", r.IP.LockDuration)
	atLeast(rep, path+".ip.bind_rps", r.IP.BindRPS, 1)
	atLeast(rep, path+".ip.bind_burst", r.IP.BindBurst, 1)
	atLeast(rep, path+".ip.search_rps", r.IP.SearchRPS, 1)
	atLeast(rep, path+".ip.search_burst", r.IP.SearchBurst, 1)
	atLeast(rep, path+".account.max_failures", r.Account.MaxFailures, 1)
	if r.Account.MaxFailures >= 5 {
		rep.warnf(path+".account.max_failures", "%d may reach the directory lockout threshold; keep it below", r.Account.MaxFailures)
	}
	positive(rep, path+".account.window", r.Account.Window)
	positive(rep, path+".account.lock_duration", r.Account.LockDuration)
	positive(rep, path+".delay.base", r.Delay.Base)
	positive(rep, path+".delay.max", r.Delay.Max)
	if r.Delay.Base > r.Delay.Max {
		rep.errorf(path+".delay.max", "must be at least delay.base (%s)", r.Delay.Base)
	}
	if r.Tarpit.Enabled {
		positive(rep, path+".tarpit.delay", r.Tarpit.Delay)
		atLeast(rep, path+".tarpit.max_conns", r.Tarpit.MaxConns, 1)
	}
	checkCIDRs(rep, path+".lockdown.allow_cidrs", r.Lockdown.AllowCIDRs)
	if r.Lockdown.Auto && len(r.Lockdown.AllowCIDRs) == 0 && len(r.Lockdown.AllowAccounts) == 0 && len(r.AllowCIDRs) == 0 {
		rep.warnf(path+".lockdown", "auto = true with no lockdown.allow_cidrs, lockdown.allow_accounts or allow_cidrs: a high-level attack_start cuts every client off until lockdown is switched off")
	}
	if !r.Enabled {
		rep.warnf(path+".enabled", "rate limiting is off: no locks, no negative cache, no lockdown; the directory takes every password guess")
	}
	if !r.ConstantTimeBindFail {
		rep.warnf(path+".constant_time_bind_fail", "off: failed-bind timing reveals whether an account exists")
	}
}

// Validate checks the section on its own.
func (i *Intrusion) Validate() error { return sectionError(i.validate, "ids") }

func (i *Intrusion) validate(path string, rep *Report) {
	positive(rep, path+".summary_interval", i.SummaryInterval)
	positive(rep, path+".quiet_period", i.QuietPeriod)
	for name, on := range map[string]bool{"spray": i.Spray.Enabled, "stuffing": i.Stuffing.Enabled, "slow_brute": i.SlowBrute.Enabled,
		"enumeration": i.Enumeration.Enabled, "recon": i.Recon.Enabled, "anomaly": i.Anomaly.Enabled, "honeytoken": i.Honeytoken.Enabled} {
		if !on {
			rep.warnf(path+"."+name+".enabled", "detector is off")
		}
	}
	if i.Spray.Enabled {
		positive(rep, path+".spray.window", i.Spray.Window)
		atLeast(rep, path+".spray.min_accounts", i.Spray.MinAccounts, 2)
	}
	if i.Stuffing.Enabled {
		positive(rep, path+".stuffing.window", i.Stuffing.Window)
		atLeast(rep, path+".stuffing.min_pairs", i.Stuffing.MinPairs, 2)
	}
	if i.SlowBrute.Enabled {
		positive(rep, path+".slow_brute.window", i.SlowBrute.Window)
		atLeast(rep, path+".slow_brute.min_failures", i.SlowBrute.MinFailures, 2)
		atLeast(rep, path+".slow_brute.max_rate_per_min", i.SlowBrute.MaxRatePerMin, 1)
	}
	if i.Enumeration.Enabled {
		atLeast(rep, path+".enumeration.min_accounts", i.Enumeration.MinAccounts, 2)
	}
	if i.Anomaly.Enabled {
		positive(rep, path+".anomaly.learn_for", i.Anomaly.LearnFor)
	}
	if i.Honeytoken.Enabled {
		positive(rep, path+".honeytoken.lock_duration", i.Honeytoken.LockDuration)
	}
	if m := i.ClientIPMasked; m.Enabled {
		p := path + ".client_ip_masked"
		if m.Window.D() < time.Minute {
			rep.errorf(p+".window", "must be at least 1m, got %s", m.Window)
		}
		atLeast(rep, p+".min_requests", m.MinRequests, 1)
		atLeast(rep, p+".min_accounts", m.MinAccounts, 2)
		if m.MinSharePercent < 1 || m.MinSharePercent > 100 {
			rep.errorf(p+".min_share_percent", "must be 1..100, got %d", m.MinSharePercent)
		}
	}
	checkCIDRs(rep, path+".client_ip_masked.ignore_cidrs", i.ClientIPMasked.IgnoreCIDRs)
}

// Validate checks the upstream on its own.
func (u *Upstream) Validate() error {
	return sectionError(func(p string, r *Report) { Validator{}.withDefaults().validateUpstream(p, "", u, r) }, "upstream")
}

func (v Validator) validateUpstream(path, name string, u *Upstream, rep *Report) {
	checkName(rep, path, name)
	v.validateUpstreamServers(path, u, rep)
	v.validateUpstreamBind(path, u, rep)
	oneOf(rep, path+".kind", u.Kind, "ad", "generic")
	if !u.AuditServiceAccount {
		rep.warnf(path+".audit_service_account", "off: an over-privileged service account is not reported")
	}
	positive(rep, path+".health_interval", u.HealthInterval)
	oneOf(rep, path+".health_check", u.HealthCheck, "rootdse", "bind", "search")
	if u.HealthCheck == "search" && u.BaseDN == "" {
		rep.errorf(path+".base_dn", "required for health_check = search")
	}
	atLeast(rep, path+".page_size", u.PageSize, 1)
	atLeast(rep, path+".failover.fail_threshold", u.Failover.FailThreshold, 1)
	atLeast(rep, path+".failover.recover_threshold", u.Failover.RecoverThreshold, 1)
	oneOf(rep, path+".failover.strategy", u.Failover.Strategy, "primary", "roundrobin")
	atLeast(rep, path+".pool.size", u.Pool.Size, 1)
	positive(rep, path+".pool.max_idle", u.Pool.MaxIdle)
	positive(rep, path+".timeouts.connect", u.Timeouts.Connect)
	positive(rep, path+".timeouts.bind", u.Timeouts.Bind)
	positive(rep, path+".timeouts.search", u.Timeouts.Search)
}

func (v Validator) validateUpstreamServers(path string, u *Upstream, rep *Report) {
	if len(u.Servers) == 0 {
		rep.errorf(path+".servers", "at least one server URL is required")
	}
	hasPlain := false
	for i, s := range u.Servers {
		p := fmt.Sprintf("%s.servers[%d]", path, i)
		pu, err := url.Parse(s)
		if err != nil || pu.Host == "" || (pu.Scheme != "ldap" && pu.Scheme != "ldaps") || pu.Path != "" || pu.User != nil {
			rep.errorf(p, "%q must be ldap://host[:port] or ldaps://host[:port]", s)
			continue
		}
		if pu.Scheme == "ldap" {
			hasPlain = true
		}
	}
	if hasPlain && !u.StartTLS {
		rep.warnf(path+".starttls", "ldap:// without StartTLS sends credentials in clear text")
	}
	if u.StartTLSRequired && !u.StartTLS {
		rep.errorf(path+".starttls_required", "requires starttls = true")
	}
	if u.TLSInsecureSkipVerify {
		rep.warnf(path+".tls_insecure_skip_verify", "certificate verification is disabled")
	}
}

func (v Validator) validateUpstreamBind(path string, u *Upstream, rep *Report) {
	src := u.BindPasswordSource()
	if u.BindDN == "" && src.IsSet() {
		rep.errorf(path+".bind_dn", "required when bind_password is set")
	}
	v.checkDN(rep, path+".bind_dn", u.BindDN)
	v.checkSecret(rep, path+".bind_password", src, u.BindDN != "")
	v.checkDN(rep, path+".base_dn", u.BaseDN)
}

// checkName warns about table names that cannot be addressed from the environment.
func checkName(rep *Report, path, name string) {
	if name == "" {
		return
	}
	if strings.ContainsAny(name, "_. ") || name != strings.ToLower(name) {
		rep.warnf(path, "name %q cannot be overridden from the environment; use lower case letters, digits and '-'", name)
	}
}

// Validate checks the profile on its own, without cross references.
func (p *Profile) Validate() error {
	return sectionError(func(path string, r *Report) {
		Validator{}.withDefaults().validateProfile(path, "", p, nil, r)
	}, "profile")
}

func (v Validator) validateProfile(path, name string, p *Profile, c *Config, rep *Report) {
	checkName(rep, path, name)
	v.validateProfileListen(path, p, rep)
	v.validateTLSOverride(path+".tls", &p.TLS, rep)
	v.validateProfileMode(path, p, c, rep)
	v.validateProfileDirectory(path, p, rep)
	v.validateProfileBind(path, p, rep)
	for _, g := range sortedKeys(p.Groups) {
		v.validateGroup(path+".groups."+g, p.Groups[g], rep)
	}
	atLeast(rep, path+".nested_depth", p.NestedDepth, 1)
	if p.NestedDepth > MaxNestedDepthCeiling {
		rep.errorf(path+".nested_depth", "%d exceeds the ceiling of %d", p.NestedDepth, MaxNestedDepthCeiling)
	}
	v.validateProfileCache(path, &p.Cache, rep)
	if p.Cache.Mode != "none" && p.Mode != "" && p.Mode != "proxy" {
		rep.warnf(path+".cache.mode", "ignored for mode = %s (no upstream to cache)", p.Mode)
	}
	v.validateProfileLimits(path, &p.Limits, rep)
	p.Ratelimit.validate(path+".ratelimit", rep)
	v.validateProfileShadow(path, p, rep)
	if p.Record.Enabled && p.Record.File == "" {
		rep.errorf(path+".record.file", "required when record.enabled = true")
	}
	atLeast(rep, path+".record.max_size_mb", p.Record.MaxSizeMB, 1)
	atLeast(rep, path+".record.max_files", p.Record.MaxFiles, 1)
}

func (v Validator) validateProfileShadow(path string, p *Profile, rep *Report) {
	v.checkFilter(rep, path+".shadow.filter", p.Shadow.Filter)
	v.checkDNList(rep, path+".shadow.bases", p.Shadow.Bases)
	atLeast(rep, path+".shadow.max_parallel", p.Shadow.MaxParallel, 1)
	positive(rep, path+".shadow.timeout", p.Shadow.Timeout)
	if p.Shadow.Enabled() && p.Mode == "honeypot" {
		rep.warnf(path+".shadow", "ignored for mode = honeypot (no directory to search)")
	}
}

func (v Validator) validateProfileListen(path string, p *Profile, rep *Report) {
	if len(p.Listen) == 0 {
		rep.errorf(path+".listen", "at least one listen address is required")
	}
	for i, addr := range p.Listen {
		lp := fmt.Sprintf("%s.listen[%d]", path, i)
		if name, ok := strings.CutPrefix(addr, ListenSystemdPrefix); ok {
			checkSystemdName(rep, lp, name)
			continue
		}
		checkListen(rep, lp, addr)
	}
	validateProxyProtocol(path+".proxy_protocol", &p.ProxyProtocol, rep)
	if !oneOf(rep, path+".transport", p.Transport, "ldaps", "ldap", "starttls", "ldap+starttls") {
		return
	}
	switch p.Transport {
	case "ldap":
		rep.warnf(path+".transport", "plain ldap without StartTLS sends credentials in clear text")
		if p.StartTLSRequired {
			rep.errorf(path+".starttls_required", "requires transport = starttls or ldap+starttls")
		}
	case "ldaps":
		if p.StartTLSRequired {
			rep.errorf(path+".starttls_required", "requires transport = starttls or ldap+starttls")
		}
	case "ldap+starttls":
		if !p.StartTLSRequired {
			rep.warnf(path+".starttls_required", "plain binds are accepted; set true to require StartTLS")
		}
	}
}

func (v Validator) validateProfileMode(path string, p *Profile, c *Config, rep *Report) {
	if oneOf(rep, path+".mode", p.Mode, "proxy", "honeypot", "mock") {
		switch p.Mode {
		case "proxy":
			if p.Upstream == "" {
				rep.errorf(path+".upstream", "required for mode = proxy")
			}
			if len(p.Bases) == 0 {
				rep.errorf(path+".bases", "at least one base is required for mode = proxy")
			}
			if len(p.Attrs.Allow) == 0 {
				rep.errorf(path+".attrs.allow", "at least one attribute is required for mode = proxy")
			}
		case "mock":
			if p.Mock.File == "" {
				rep.errorf(path+".mock.file", "required for mode = mock")
			}
		}
	}
	if p.Upstream != "" && c != nil {
		u, ok := c.Upstreams[p.Upstream]
		if !ok {
			rep.errorf(path+".upstream", "upstream %q is not defined", p.Upstream)
		} else if p.Mode == "proxy" && p.Filter == "" && u.Kind == "generic" {
			// AD gets the default person/user/enabled filter; a generic
			// directory has none, so without a filter every object under
			// the bases (service accounts, groups, devices) is a user.
			rep.errorf(path+".filter", "required for a generic upstream (SPEC §3.4: no default filter outside kind = ad)")
		}
	}
}

func (v Validator) validateProfileDirectory(path string, p *Profile, rep *Report) {
	if p.VirtualBase == "" {
		rep.errorf(path+".virtual_base", "required")
	} else {
		v.checkDN(rep, path+".virtual_base", p.VirtualBase)
		vb := dnKey(p.VirtualBase)
		for i, b := range p.Bases {
			if bk := dnKey(b); vb == bk || strings.HasSuffix(vb, ","+bk) {
				rep.errorf(path+".virtual_base", "%q is equal to or under bases[%d] %q: a virtual DN must not be a real one", p.VirtualBase, i, b)
			}
		}
	}
	v.checkDNList(rep, path+".bases", p.Bases)
	v.checkFilter(rep, path+".filter", p.Filter)
	v.checkFilter(rep, path+".exclude_filter", p.ExcludeFilter)
	for i, a := range p.Attrs.Allow {
		if t := strings.TrimSpace(a); t == "*" || t == "+" {
			rep.errorf(fmt.Sprintf("%s.attrs.allow[%d]", path, i), "'%s' is not allowed; list attributes explicitly", t)
		}
	}
	for _, k := range sortedKeys(p.Attrs.Computed) {
		checkProfileTemplate(rep, path+".attrs.computed."+k, p.Attrs.Computed[k])
	}
	for _, k := range sortedKeys(p.HoneytokenTemplate) {
		checkProfileTemplate(rep, path+".honeytoken_template."+k, p.HoneytokenTemplate[k])
	}
	if p.RDNAttr == "" {
		rep.errorf(path+".rdn_attr", "required")
	}
}

func (v Validator) validateProfileBind(path string, p *Profile, rep *Report) {
	cb := p.ClientBind
	if cb.DN != "" {
		v.checkDN(rep, path+".client_bind.dn", cb.DN)
	} else if cb.PasswordSource().IsSet() || cb.PasswordHash.IsSet() {
		rep.errorf(path+".client_bind.dn", "required when client_bind.password is set")
	}
	if cb.PasswordHash.IsSet() {
		if cb.PasswordSource().IsSet() {
			rep.errorf(path+".client_bind.password_hash", "mutually exclusive with password, password_file and password_env")
		}
		if cb.PasswordHash.Reveal() == secret.Redacted {
			rep.errorf(path+".client_bind.password_hash", "is the masked placeholder; a rendered configuration cannot be applied with it")
		} else if err := ValidateArgon2PHC(cb.PasswordHash.Reveal()); err != nil {
			rep.errorf(path+".client_bind.password_hash", "%v", err)
		}
	}
	v.checkSecret(rep, path+".client_bind.password", cb.PasswordSource(), cb.DN != "" && !cb.PasswordHash.IsSet())
	if p.AnonymousBind {
		rep.warnf(path+".anonymous_bind", "anonymous bind is enabled")
	}
	// A user bind by UPN, DOMAIN\user or sAMAccountName is forwarded to the
	// directory as is (SPEC §4.3): an account the profile hides through
	// filter or exclude_filter still authenticates unless membership is
	// required.
	if p.UserBind.Allow && !p.UserBind.RequireMembership && (p.ExcludeFilter != "" || (p.Filter != "" && p.Filter != DefaultADFilter)) {
		rep.warnf(path+".user_bind.require_membership", "accounts outside the profile (filter, exclude_filter) can still authenticate through it; set require_membership = true to refuse them")
	}
}

func (v Validator) validateProfileCache(path string, c *Cache, rep *Report) {
	if !oneOf(rep, path+".cache.mode", c.Mode, "none", "ttl", "replica") {
		return
	}
	switch c.Mode {
	case "ttl":
		positive(rep, path+".cache.ttl", c.TTL)
		atLeast(rep, path+".cache.max_entries", c.MaxEntries, 1)
	case "replica":
		positive(rep, path+".cache.sync_interval", c.SyncInterval)
	}
	if c.StaleWhileDown && c.Mode != "none" {
		positive(rep, path+".cache.stale_max", c.StaleMax)
	}
}

func (v Validator) validateProfileLimits(path string, l *Limits, rep *Report) {
	atLeast(rep, path+".limits.max_result_size", l.MaxResultSize, 1)
	atLeast(rep, path+".limits.max_filter_depth", l.MaxFilterDepth, 1)
	atLeast(rep, path+".limits.max_filter_len", l.MaxFilterLen, 1)
	if l.MaxRequestBytes <= 0 {
		rep.errorf(path+".limits.max_request_bytes", "must be positive")
	} else if l.MaxRequestBytes > MaxRequestBytesCeiling {
		rep.errorf(path+".limits.max_request_bytes", "%d exceeds the ceiling of %d bytes (one request is buffered in memory)", l.MaxRequestBytes, MaxRequestBytesCeiling)
	}
	if l.MaxFilterDepth > MaxFilterDepthCap {
		rep.errorf(path+".limits.max_filter_depth", "%d exceeds the parser's hard cap %d", l.MaxFilterDepth, MaxFilterDepthCap)
	}
	atLeast(rep, path+".limits.max_conns_per_ip", l.MaxConnsPerIP, 1)
	if l.MaxConnsPerIP > MaxConnsPerIPCeiling {
		rep.errorf(path+".limits.max_conns_per_ip", "%d exceeds the ceiling of %d", l.MaxConnsPerIP, MaxConnsPerIPCeiling)
	}
	positive(rep, path+".limits.idle_timeout", l.IdleTimeout)
	atLeast(rep, path+".limits.upstream_parallel", l.UpstreamParallel, 1)
}

func (v Validator) checkDN(rep *Report, path, dn string) {
	if dn == "" {
		return
	}
	if err := v.ParseDN(dn); err != nil {
		rep.errorf(path, "%v", err)
	}
}

func (v Validator) checkDNList(rep *Report, path string, dns []string) {
	for i, dn := range dns {
		v.checkDN(rep, fmt.Sprintf("%s[%d]", path, i), dn)
	}
}

func (v Validator) checkFilter(rep *Report, path, f string) {
	if f == "" {
		return
	}
	if err := v.ParseFilter(f); err != nil {
		rep.errorf(path, "%v", err)
	}
}

func (v Validator) validateTLSOverride(path string, t *TLSOverride, rep *Report) {
	if t.Mode != nil {
		oneOf(rep, path+".mode", *t.Mode, "builtin-ca", "external")
	}
	if t.KeyType != nil {
		oneOf(rep, path+".key_type", *t.KeyType, "ecdsa-p256", "rsa-2048")
	}
	if t.MinVersion != nil {
		oneOf(rep, path+".min_version", *t.MinVersion, "1.2", "1.3")
	}
	if t.ClientAuth != nil {
		oneOf(rep, path+".client_auth", *t.ClientAuth, "none", "request", "require")
	}
	if t.Mode != nil && *t.Mode == "external" {
		if t.Cert == nil || t.Key == nil {
			rep.errorf(path+".cert", "cert and key are required for mode = external")
		} else {
			v.checkCertFile(rep, path+".cert", *t.Cert, 0, nil)
		}
	}
	if t.ClientAuth != nil && *t.ClientAuth != "none" && (t.ClientCA == nil || *t.ClientCA == "") && (v.globalClientCA == "") {
		rep.errorf(path+".client_ca", "required for client_auth = %s (not set here nor in [tls])", *t.ClientAuth)
	}
}

func (v Validator) validateGroup(path string, g Group, rep *Report) {
	oneOf(rep, path+".objectclass", g.ObjectClass, "groupOfNames", "group", "posixGroup")
	if g.ObjectClass == "posixGroup" && g.GIDNumber <= 0 {
		rep.errorf(path+".gid_number", "required for objectclass = posixGroup")
	}
	v.checkFilter(rep, path+".members.filter", g.Members.Filter)
	v.checkDNList(rep, path+".members.bases", g.Members.Bases)
	v.checkDNList(rep, path+".members.ad_groups", g.Members.ADGroups)
}

func (r *RatelimitPatch) validate(path string, rep *Report) {
	if r.Enabled != nil && !*r.Enabled {
		rep.warnf(path+".enabled", "rate limiting is off for this profile: no locks, no negative cache; the directory takes every password guess")
	}
	if r.ConstantTimeBindFail != nil && !*r.ConstantTimeBindFail {
		rep.warnf(path+".constant_time_bind_fail", "off: failed-bind timing reveals whether an account exists")
	}
	if r.NegativeCacheTTL != nil {
		positive(rep, path+".negative_cache_ttl", *r.NegativeCacheTTL)
	}
	if r.LockResponse != nil {
		oneOf(rep, path+".lock_response", *r.LockResponse, "invalidCredentials", "busy")
	}
	if r.AllowCIDRs != nil {
		checkCIDRs(rep, path+".allow_cidrs", *r.AllowCIDRs)
	}
	if r.Lockdown.AllowCIDRs != nil {
		checkCIDRs(rep, path+".lockdown.allow_cidrs", *r.Lockdown.AllowCIDRs)
	}
	for k, p := range map[string]*int{
		".ip.max_failures": r.IP.MaxFailures, ".ip.bind_rps": r.IP.BindRPS, ".ip.bind_burst": r.IP.BindBurst,
		".ip.search_rps": r.IP.SearchRPS, ".ip.search_burst": r.IP.SearchBurst,
		".account.max_failures": r.Account.MaxFailures, ".tarpit.max_conns": r.Tarpit.MaxConns,
	} {
		if p != nil {
			atLeast(rep, path+k, *p, 1)
		}
	}
	if r.Account.MaxFailures != nil && *r.Account.MaxFailures >= 5 {
		rep.warnf(path+".account.max_failures", "%d may reach the directory lockout threshold; keep it below", *r.Account.MaxFailures)
	}
	for k, p := range map[string]*Duration{
		".ip.window": r.IP.Window, ".ip.lock_duration": r.IP.LockDuration,
		".account.window": r.Account.Window, ".account.lock_duration": r.Account.LockDuration,
		".delay.base": r.Delay.Base, ".delay.max": r.Delay.Max, ".tarpit.delay": r.Tarpit.Delay,
	} {
		if p != nil {
			positive(rep, path+k, *p)
		}
	}
}

// validateProfilesCross checks uniqueness across profiles: virtual bases and listen ports.
func (v Validator) validateProfilesCross(c *Config, rep *Report) {
	type listener struct {
		path string
		host string
	}
	bases := map[string]string{}
	ports := map[int][]listener{}
	sockets := map[string]string{}
	files := map[string]string{}
	if c.Events.File.Enabled && c.Events.File.Path != "" {
		files[filepath.Clean(c.Events.File.Path)] = "events.file.path"
	}
	for _, name := range sortedKeys(c.Profiles) {
		p := c.Profiles[name]
		path := "profile." + name
		if f := p.Record.File; f != "" {
			if other, dup := files[filepath.Clean(f)]; dup {
				rep.errorf(path+".record.file", "%q is already written by %s", f, other)
			} else {
				files[filepath.Clean(f)] = path + ".record.file"
			}
		}
		vb := strings.ToLower(strings.ReplaceAll(p.VirtualBase, " ", ""))
		if vb != "" {
			if other, dup := bases[vb]; dup {
				rep.errorf(path+".virtual_base", "%q is already used by %s", p.VirtualBase, other)
			} else {
				bases[vb] = path
			}
		}
		for i, addr := range p.Listen {
			lp := fmt.Sprintf("%s.listen[%d]", path, i)
			if strings.HasPrefix(addr, ListenSystemdPrefix) {
				if other, dup := sockets[addr]; dup {
					rep.errorf(lp, "%q is already used by %s", addr, other)
				} else {
					sockets[addr] = lp
				}
				continue
			}
			h, port, ok := checkListen(&Report{}, lp, addr)
			if !ok {
				continue
			}
			for _, other := range ports[port] {
				if other.host == h || isWildcardHost(other.host) || isWildcardHost(h) {
					rep.errorf(lp, "%q conflicts with %s", addr, other.path)
					break
				}
			}
			ports[port] = append(ports[port], listener{path: lp, host: h})
		}
	}
}

// Validate checks the section on its own.
func (e *Events) Validate() error {
	return sectionError(func(p string, r *Report) { Validator{}.withDefaults().validateEvents(p, e, r) }, "events")
}

func (v Validator) validateEvents(path string, e *Events, rep *Report) {
	atLeast(rep, path+".buffer_size", e.BufferSize, 1)
	if e.HashAccounts && e.SaltFile == "" {
		rep.errorf(path+".salt_file", "required when hash_accounts = true")
	}
	if len(e.Include) > 0 && len(e.Exclude) > 0 {
		rep.errorf(path+".include", "include and exclude are mutually exclusive")
	}
	if e.Stdout.Enabled {
		oneOf(rep, path+".stdout.format", e.Stdout.Format, "json")
	}
	if e.File.Enabled {
		if e.File.Path == "" {
			rep.errorf(path+".file.path", "required when file.enabled = true")
		}
		atLeast(rep, path+".file.max_size_mb", e.File.MaxSizeMB, 1)
		atLeast(rep, path+".file.max_files", e.File.MaxFiles, 1)
	}
	if e.Syslog.Enabled {
		oneOf(rep, path+".syslog.network", e.Syslog.Network, "udp", "tcp", "unix")
		if e.Syslog.Address == "" {
			rep.errorf(path+".syslog.address", "required when syslog.enabled = true")
		}
	}
	names := map[string]bool{}
	for i := range e.Webhooks {
		w := &e.Webhooks[i]
		p := fmt.Sprintf("%s.webhook[%d]", path, i)
		if w.Name == "" {
			rep.errorf(p+".name", "required")
		} else if names[w.Name] {
			rep.errorf(p+".name", "%q is already used", w.Name)
		}
		names[w.Name] = true
		checkHTTPURL(rep, p+".url", w.URL)
		atLeast(rep, p+".batch_size", w.BatchSize, 1)
		positive(rep, p+".batch_interval", w.BatchInterval)
		positive(rep, p+".timeout", w.Timeout)
		validateRetry(rep, p+".retry", w.Retry)
		v.checkSecret(rep, p+".hmac_secret", w.HMACSecretSource(), false)
		v.checkHeaders(rep, p, w.Headers, w.HeadersFile)
		atLeast(rep, p+".queue_size", w.QueueSize, 1)
		oneOf(rep, p+".on_overflow", w.OnOverflow, "drop_oldest", "block")
	}
}

func checkHTTPURL(rep *Report, path, raw string) {
	if raw == "" {
		rep.errorf(path, "required")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		rep.errorf(path, "%q must be an http(s) URL", raw)
		return
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		rep.warnf(path, "plain http to a non-loopback host")
	}
}

func validateRetry(rep *Report, path string, r Retry) {
	if r.Max < 0 {
		rep.errorf(path+".max", "must not be negative")
	}
	positive(rep, path+".backoff", r.Backoff)
	positive(rep, path+".max_backoff", r.MaxBackoff)
	if r.Backoff > r.MaxBackoff {
		rep.errorf(path+".max_backoff", "must be at least retry.backoff (%s)", r.Backoff)
	}
}

// Validate checks the section on its own.
func (n *Notify) Validate() error {
	return sectionError(func(p string, r *Report) { Validator{}.withDefaults().validateNotify(p, n, r) }, "notify")
}

func (v Validator) validateNotify(path string, n *Notify, rep *Report) {
	positive(rep, path+".cooldown", n.Cooldown)
	positive(rep, path+".digest_interval", n.DigestInterval)
	names := map[string]bool{}
	for i := range n.Channels {
		c := &n.Channels[i]
		p := fmt.Sprintf("%s.channel[%d]", path, i)
		if c.Name == "" {
			rep.errorf(p+".name", "required")
		} else if names[c.Name] {
			rep.errorf(p+".name", "%q is already used", c.Name)
		}
		names[c.Name] = true
		oneOf(rep, p+".min_level", c.MinLevel, "low", "medium", "high")
		for j, e := range c.Events {
			if !slices.Contains(EventKinds, e) && NotifyLockAliases[e] == "" {
				rep.errorf(fmt.Sprintf("%s.events[%d]", p, j), "unknown event type %q", e)
			}
		}
		if len(c.Events) == 0 {
			rep.warnf(p+".events", "empty: the channel receives nothing")
		}
		positive(rep, p+".timeout", c.Timeout)
		validateRetry(rep, p+".retry", c.Retry)
		if !oneOf(rep, p+".type", c.Type, "telegram", "virola", "email", "webhook") {
			continue
		}
		checkForeignChannelKeys(rep, p, c)
		switch c.Type {
		case "telegram":
			v.checkSecret(rep, p+".bot_token", c.BotTokenSource(), true)
			if c.ChatID == "" {
				rep.errorf(p+".chat_id", "required for type = telegram")
			}
			checkHTTPURL(rep, p+".api_base", c.APIBase)
			oneOf(rep, p+".parse_mode", c.ParseMode, "MarkdownV2", "HTML", "none")
		case "virola":
			v.validateVirolaChannel(p, c, rep)
		case "email":
			v.validateEmailChannel(p, c, rep)
		case "webhook":
			v.validateWebhookChannel(p, c, rep)
		}
	}
}

func (v Validator) validateVirolaChannel(p string, c *Channel, rep *Report) {
	checkHTTPURL(rep, p+".base_url", c.BaseURL)
	v.checkSecret(rep, p+".token", c.TokenSource(), true)
	if (c.RoomID == 0) == (c.UserID == 0) {
		rep.errorf(p+".room_id", "exactly one of room_id or user_id is required for type = virola")
	} else {
		checkVirolaPath(rep, p+".path_template", c)
	}
	if c.TLSInsecureSkipVerify {
		rep.warnf(p+".tls_insecure_skip_verify", "certificate verification is disabled")
	}
}

// checkVirolaPath accepts an absolute path that names the configured
// destination through exactly its own placeholder, so an override cannot
// silently post to another room or leave the target out.
func checkVirolaPath(rep *Report, path string, c *Channel) {
	tpl := c.PathTemplate
	if tpl == "" {
		return
	}
	want, other := "{room_id}", "{user_id}"
	if c.UserID != 0 {
		want, other = other, want
	}
	rest := strings.ReplaceAll(tpl, want, "")
	switch {
	case !strings.HasPrefix(tpl, "/") || strings.HasPrefix(tpl, "//"):
		rep.errorf(path, "%q must be an absolute path starting with a single /", tpl)
	case strings.Count(tpl, want) != 1:
		rep.errorf(path, "%q must contain %s exactly once", tpl, want)
	case strings.Contains(tpl, other):
		rep.errorf(path, "%q uses %s, but the channel sets the other id", tpl, other)
	case strings.ContainsAny(rest, "{}?#%\\ ") || slices.Contains(strings.Split(rest, "/"), ".."):
		rep.errorf(path, "%q: only path characters and %s are allowed", tpl, want)
	}
}

func (v Validator) validateEmailChannel(p string, c *Channel, rep *Report) {
	if c.SMTPHost == "" {
		rep.errorf(p+".smtp_host", "required for type = email")
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		rep.errorf(p+".smtp_port", "invalid port %d", c.SMTPPort)
	}
	if oneOf(rep, p+".tls", c.TLSMode, "starttls", "tls", "none") && c.TLSMode == "none" {
		rep.warnf(p+".tls", "SMTP without TLS")
	}
	v.checkSecret(rep, p+".password", c.PasswordSource(), c.Username != "")
	if c.From == "" {
		rep.errorf(p+".from", "required for type = email")
	}
	if len(c.To) == 0 {
		rep.errorf(p+".to", "at least one recipient is required for type = email")
	}
	checkNotifyTemplate(rep, p+".subject_template", c.SubjectTemplate)
}

// checkNotifyTemplate parses a notification template with stubs of the
// functions internal/notify provides.
func checkNotifyTemplate(rep *Report, path, text string) {
	if text == "" {
		return
	}
	funcs := template.FuncMap{}
	for _, name := range NotifyTemplateFuncs {
		funcs[name] = func(...any) any { return nil }
	}
	if _, err := template.New(path).Funcs(funcs).Parse(text); err != nil {
		rep.errorf(path, "%v", err)
	}
}

// checkProfileTemplate parses a profile attribute template with stubs of
// the functions internal/profile provides; a constant regexReplace pattern
// must compile.
func checkProfileTemplate(rep *Report, path, text string) {
	funcs := template.FuncMap{}
	for _, name := range ProfileTemplateFuncs {
		funcs[name] = func(...any) any { return nil }
	}
	tpl, err := template.New(path).Funcs(funcs).Parse(text)
	if err != nil {
		rep.errorf(path, "%v", err)
		return
	}
	walkTemplate(tpl.Root, func(n parse.Node) {
		args := regexReplaceArgs(n)
		if len(args) == 0 {
			return
		}
		if len(args) != 3 {
			rep.errorf(path, "regexReplace takes pattern, replacement and value, got %d arguments", len(args))
			return
		}
		if s, ok := args[0].(*parse.StringNode); ok {
			if _, err := regexp.Compile(s.Text); err != nil {
				rep.errorf(path, "regexReplace pattern: %v", err)
			}
		}
	})
}

// regexReplaceArgs returns the arguments of a regexReplace command node
// (including a piped value as the last one), or nil.
func regexReplaceArgs(n parse.Node) []parse.Node {
	pipe, ok := n.(*parse.PipeNode)
	if !ok {
		return nil
	}
	var out []parse.Node
	for i, cmd := range pipe.Cmds {
		if len(cmd.Args) == 0 {
			continue
		}
		if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok && id.Ident == "regexReplace" {
			out = append(out, cmd.Args[1:]...)
			if i > 0 {
				out = append(out, pipe.Cmds[i-1])
			}
			return out
		}
	}
	return nil
}

// walkTemplate calls fn on every pipeline of a template tree.
func walkTemplate(n parse.Node, fn func(parse.Node)) {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			walkTemplate(c, fn)
		}
	case *parse.ActionNode:
		walkTemplate(n.Pipe, fn)
	case *parse.PipeNode:
		if n == nil {
			return
		}
		fn(n)
		for _, c := range n.Cmds {
			for _, a := range c.Args {
				walkTemplate(a, fn)
			}
		}
	case *parse.IfNode:
		walkTemplate(n.Pipe, fn)
		walkTemplate(n.List, fn)
		walkTemplate(n.ElseList, fn)
	case *parse.RangeNode:
		walkTemplate(n.Pipe, fn)
		walkTemplate(n.List, fn)
		walkTemplate(n.ElseList, fn)
	case *parse.WithNode:
		walkTemplate(n.Pipe, fn)
		walkTemplate(n.List, fn)
		walkTemplate(n.ElseList, fn)
	}
}

func (v Validator) validateWebhookChannel(p string, c *Channel, rep *Report) {
	checkHTTPURL(rep, p+".url", c.URL)
	oneOf(rep, p+".method", c.Method, "POST", "PUT", "PATCH")
	checkNotifyTemplate(rep, p+".body_template", c.BodyTemplate)
	v.checkSecret(rep, p+".hmac_secret", c.HMACSecretSource(), false)
	v.checkHeaders(rep, p, c.Headers, c.HeadersFile)
}

// Validate checks the section on its own.
func (a *API) Validate() error {
	return sectionError(func(p string, r *Report) { Validator{}.withDefaults().validateAPI(p, a, r) }, "api")
}

func (v Validator) validateAPI(path string, a *API, rep *Report) {
	if a.CORS {
		rep.errorf(path+".cors", "CORS cannot be enabled")
	}
	if a.RateLimitRPS < 0 {
		rep.errorf(path+".rate_limit_rps", "must not be negative")
	}
	if a.MaxStreams < 1 {
		rep.errorf(path+".max_streams", "must be at least 1")
	}
	oneOf(rep, path+".client_auth", a.ClientAuth, "none", "require")
	if a.ClientAuth == "require" && a.ClientCA == "" {
		rep.errorf(path+".client_ca", "required for client_auth = require")
	}
	if a.TLS.Cert != "" || a.TLS.Key != "" {
		if a.TLS.Cert == "" || a.TLS.Key == "" {
			rep.errorf(path+".tls.cert", "cert and key must be set together")
		}
		if a.TLS.Builtin {
			rep.errorf(path+".tls.builtin", "cannot be combined with tls.cert and tls.key")
		}
	}
	if a.Enabled {
		v.validateAPIListen(path, a, rep)
	} else if a.Metrics.Enabled && a.Metrics.Listen != "" {
		// A separate metrics listener runs even with the API off.
		hasTLS := a.TLS.Builtin || a.TLS.Cert != ""
		if mh, _, mok := checkListen(rep, path+".metrics.listen", a.Metrics.Listen); mok && !isLoopbackHost(mh) && !hasTLS {
			rep.errorf(path+".metrics.listen", "TLS is mandatory when the metrics listener is not loopback: set tls.builtin = true or tls.cert and tls.key")
		}
	}
	v.validateAPITokens(path, a.Tokens, rep)
}

func (v Validator) validateAPITokens(path string, tokens []APIToken, rep *Report) {
	names := map[string]bool{}
	for i := range tokens {
		p := fmt.Sprintf("%s.token[%d]", path, i)
		t := &tokens[i]
		if t.Name == "" {
			rep.errorf(p+".name", "required")
		} else if names[t.Name] {
			rep.errorf(p+".name", "%q is already used", t.Name)
		}
		names[t.Name] = true
		v.validateAPIToken(p, t, rep)
	}
}

func (v Validator) validateAPIListen(path string, a *API, rep *Report) {
	host, _, ok := checkListen(rep, path+".listen", a.Listen)
	hasTLS := a.TLS.Builtin || a.TLS.Cert != ""
	if ok && !isLoopbackHost(host) && !hasTLS {
		rep.errorf(path+".tls", "TLS is mandatory when listen is not loopback: set tls.builtin = true or tls.cert and tls.key")
	}
	if a.ClientAuth == "require" && !hasTLS {
		rep.errorf(path+".tls", "client_auth = require needs TLS: set tls.builtin = true or tls.cert and tls.key")
	}
	if a.Metrics.Listen != "" {
		if mh, _, mok := checkListen(rep, path+".metrics.listen", a.Metrics.Listen); mok && !isLoopbackHost(mh) && !hasTLS {
			rep.errorf(path+".metrics.listen", "TLS is mandatory when the metrics listener is not loopback: set tls.builtin = true or tls.cert and tls.key")
		}
	}
	if a.Metrics.Enabled && a.Metrics.Public {
		rep.warnf(path+".metrics.public", "/metrics is served without a token")
	}
}

func (v Validator) validateAPIToken(p string, t *APIToken, rep *Report) {
	src := t.TokenSource()
	v.checkSecret(rep, p+".token", src, true)
	if src.Kind() == "inline" && len(t.Token.Reveal()) < 32 {
		rep.errorf(p+".token", "must be at least 32 bytes")
	}
	if len(t.Scopes) == 0 {
		rep.errorf(p+".scopes", "at least one scope is required")
	}
	for j, s := range t.Scopes {
		oneOf(rep, fmt.Sprintf("%s.scopes[%d]", p, j), s, "events:read", "locks:read", "locks:write", "status:read", "admin")
	}
	checkCIDRs(rep, p+".allow_cidrs", t.AllowCIDRs)
}

// sectionError adapts a path-based validate function to the Validate() error form.
func sectionError(fn func(string, *Report), path string) error {
	rep := &Report{}
	fn(path, rep)
	if rep.OK() {
		return nil
	}
	return rep
}

// Argon2id cost bounds for client_bind.password_hash (SPEC §9 defaults are
// t=3, m=64 MiB, p=4): a hash with absurd costs would let one bind exhaust
// the process, a weak one would make the service password crackable.
const (
	Argon2MinMemoryKiB = 8 * 1024
	Argon2MaxMemoryKiB = 1024 * 1024
	Argon2MinTime      = 1
	Argon2MaxTime      = 16
	Argon2MinThreads   = 1
	Argon2MaxThreads   = 16
)

var argon2PHCRe = regexp.MustCompile(`^\$argon2id\$v=19\$m=([0-9]{1,10}),t=([0-9]{1,10}),p=([0-9]{1,3})\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)

// ValidateArgon2PHC checks the shape and the cost bounds of an argon2id PHC
// string ($argon2id$v=19$m=...,t=...,p=...$salt$hash). The profile package
// parses it for real; the same bounds apply there.
func ValidateArgon2PHC(s string) error {
	m := argon2PHCRe.FindStringSubmatch(s)
	if m == nil {
		return errors.New("must be an argon2id PHC string ($argon2id$v=19$m=...,t=...,p=...$salt$hash)")
	}
	mem, errM := strconv.ParseUint(m[1], 10, 64)
	t, errT := strconv.ParseUint(m[2], 10, 64)
	p, errP := strconv.ParseUint(m[3], 10, 64)
	if errors.Join(errM, errT, errP) != nil {
		return errors.New("argon2id cost parameters are out of range")
	}
	return CheckArgon2Costs(mem, t, p)
}

// CheckArgon2Costs applies the argon2id cost bounds.
func CheckArgon2Costs(memKiB, t, p uint64) error {
	switch {
	case memKiB < Argon2MinMemoryKiB || memKiB > Argon2MaxMemoryKiB:
		return fmt.Errorf("argon2id m=%d KiB is outside %d..%d", memKiB, Argon2MinMemoryKiB, Argon2MaxMemoryKiB)
	case t < Argon2MinTime || t > Argon2MaxTime:
		return fmt.Errorf("argon2id t=%d is outside %d..%d", t, Argon2MinTime, Argon2MaxTime)
	case p < Argon2MinThreads || p > Argon2MaxThreads:
		return fmt.Errorf("argon2id p=%d is outside %d..%d", p, Argon2MinThreads, Argon2MaxThreads)
	case memKiB < 8*p:
		return fmt.Errorf("argon2id m=%d KiB is below 8*p", memKiB)
	}
	return nil
}

// Ceilings for resource limits (SPEC §9: every limit bounds memory, so a
// value that cannot be meant disables the bound in practice).
const (
	MaxRequestBytesCeiling = 64 << 20 // one request is buffered whole
	MaxFilterDepthCap      = 64       // ldapfilter.HardMaxDepth; kept equal by a test there
	MaxConnsPerIPCeiling   = 65535
	MaxNestedDepthCeiling  = 100
)

// dnKey folds a DN for suffix comparison: lower case, no spaces around separators.
func dnKey(dn string) string {
	parts := strings.Split(strings.ToLower(dn), ",")
	for i, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		for j := range kv {
			kv[j] = strings.TrimSpace(kv[j])
		}
		parts[i] = strings.Join(kv, "=")
	}
	return strings.Join(parts, ",")
}

// checkForeignChannelKeys refuses keys of another channel type: a misplaced
// secret would be read for nothing, and tls_insecure_skip_verify on a
// channel that does not honor it would look like it does.
func checkForeignChannelKeys(rep *Report, p string, c *Channel) {
	def := DefaultChannel()
	set := func(key string, present bool, types ...string) {
		if !present || slices.Contains(types, c.Type) {
			return
		}
		rep.errorf(p+"."+key, "not a key of a %s channel (used by %s)", c.Type, strings.Join(types, "/"))
	}
	set("bot_token", c.BotToken.IsSet() || c.BotTokenFile != "" || c.BotTokenEnv != "", "telegram")
	set("chat_id", c.ChatID != "", "telegram")
	set("parse_mode", c.ParseMode != def.ParseMode, "telegram")
	set("api_base", c.APIBase != def.APIBase, "telegram")
	set("base_url", c.BaseURL != "", "virola")
	set("token", c.Token.IsSet() || c.TokenFile != "" || c.TokenEnv != "", "virola")
	set("room_id", c.RoomID != 0, "virola")
	set("user_id", c.UserID != 0, "virola")
	set("path_template", c.PathTemplate != "", "virola")
	set("tls_ca_file", c.TLSCAFile != "", "virola")
	set("tls_insecure_skip_verify", c.TLSInsecureSkipVerify, "virola")
	set("smtp_host", c.SMTPHost != "", "email")
	set("smtp_port", c.SMTPPort != def.SMTPPort, "email")
	set("tls", c.TLSMode != def.TLSMode, "email")
	set("username", c.Username != "", "email")
	set("password", c.Password.IsSet() || c.PasswordFile != "" || c.PasswordEnv != "", "email")
	set("from", c.From != "", "email")
	set("to", len(c.To) > 0, "email")
	set("subject_template", c.SubjectTemplate != "", "email")
	set("url", c.URL != "", "webhook")
	set("method", c.Method != def.Method, "webhook")
	set("headers", len(c.Headers) > 0 || c.HeadersFile != "", "webhook")
	set("body_template", c.BodyTemplate != "", "webhook")
	set("hmac_secret", c.HMACSecret.IsSet() || c.HMACSecretFile != "" || c.HMACSecretEnv != "", "webhook")
}

// validatePathCollisions refuses configurations where one file plays two
// roles: a secret *_file that is a private key, salt or token file (its
// content would be sent to the upstream as a password), or an output file
// (events.file.path, record.file) that is any input (the daemon would
// append events to the CA key or the configuration).
func validatePathCollisions(c *Config, rep *Report) {
	type named struct{ path, key string }
	var keys, inputs, secrets, outputs []named
	add := func(list *[]named, file, key string) {
		if file != "" {
			*list = append(*list, named{filepath.Clean(file), key})
		}
	}
	if c.TLS.CADir != "" {
		add(&keys, filepath.Join(c.TLS.CADir, "ca.key"), "tls.ca_dir/ca.key")
		add(&keys, filepath.Join(c.TLS.CADir, "server.key"), "tls.ca_dir/server.key")
		add(&inputs, filepath.Join(c.TLS.CADir, "ca.crt"), "tls.ca_dir/ca.crt")
		add(&inputs, filepath.Join(c.TLS.CADir, "server.crt"), "tls.ca_dir/server.crt")
	}
	add(&keys, c.TLS.Key, "tls.key")
	add(&inputs, c.TLS.Cert, "tls.cert")
	add(&inputs, c.TLS.ClientCA, "tls.client_ca")
	add(&keys, c.API.TLS.Key, "api.tls.key")
	add(&inputs, c.API.TLS.Cert, "api.tls.cert")
	add(&inputs, c.API.ClientCA, "api.client_ca")
	add(&keys, c.Events.SaltFile, "events.salt_file")
	for i := range c.API.Tokens {
		add(&keys, c.API.Tokens[i].TokenFile, fmt.Sprintf("api.token[%d].token_file", i))
	}
	for _, name := range sortedKeys(c.Upstreams) {
		u := c.Upstreams[name]
		add(&secrets, u.BindPasswordFile, "upstream."+name+".bind_password_file")
		add(&inputs, u.TLSCAFile, "upstream."+name+".tls_ca_file")
	}
	for _, name := range sortedKeys(c.Profiles) {
		p := c.Profiles[name]
		pp := "profile." + name
		add(&secrets, p.ClientBind.PasswordFile, pp+".client_bind.password_file")
		add(&inputs, p.Mock.File, pp+".mock.file")
		if p.TLS.Key != nil {
			add(&keys, *p.TLS.Key, pp+".tls.key")
		}
		if p.TLS.Cert != nil {
			add(&inputs, *p.TLS.Cert, pp+".tls.cert")
		}
		if p.TLS.ClientCA != nil {
			add(&inputs, *p.TLS.ClientCA, pp+".tls.client_ca")
		}
		add(&outputs, p.Record.File, pp+".record.file")
	}
	for i := range c.Events.Webhooks {
		w := &c.Events.Webhooks[i]
		add(&secrets, w.HMACSecretFile, fmt.Sprintf("events.webhook[%d].hmac_secret_file", i))
		add(&secrets, w.HeadersFile, fmt.Sprintf("events.webhook[%d].headers_file", i))
		add(&inputs, w.TLSCAFile, fmt.Sprintf("events.webhook[%d].tls_ca_file", i))
	}
	for i := range c.Notify.Channels {
		ch := &c.Notify.Channels[i]
		cp := fmt.Sprintf("notify.channel[%d]", i)
		add(&secrets, ch.BotTokenFile, cp+".bot_token_file")
		add(&secrets, ch.TokenFile, cp+".token_file")
		add(&secrets, ch.PasswordFile, cp+".password_file")
		add(&secrets, ch.HMACSecretFile, cp+".hmac_secret_file")
		add(&secrets, ch.HeadersFile, cp+".headers_file")
		add(&inputs, ch.TLSCAFile, cp+".tls_ca_file")
	}
	if c.Events.File.Enabled {
		add(&outputs, c.Events.File.Path, "events.file.path")
	}
	for _, s := range secrets {
		for _, k := range keys {
			if s.path == k.path {
				rep.errorf(s.key, "%q is %s: a private key, salt or token must not be read as this secret", s.path, k.key)
			}
		}
	}
	all := append(append(append([]named(nil), keys...), inputs...), secrets...)
	for _, o := range outputs {
		for _, in := range all {
			if o.path == in.path {
				rep.errorf(o.key, "%q is also %s: an output file must not be an input", o.path, in.key)
			}
		}
	}
}
