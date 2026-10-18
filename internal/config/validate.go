package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/alstdev/aldap/internal/secret"
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
	// StrictFiles turns unreadable secret and certificate files into errors.
	// Offline `aldap check` leaves it false because such files are often
	// mounted only at run time (/run/secrets); `aldap run` sets it.
	StrictFiles bool
	// ParseFilter checks LDAP filter syntax; defaults to a structural check
	// until the RFC 4515 parser is wired in.
	ParseFilter func(string) error
	// ParseDN checks DN syntax; defaults to a structural check until the
	// RFC 4514 parser is wired in.
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
		v.ParseFilter = basicFilterSyntax
	}
	if v.ParseDN == nil {
		v.ParseDN = basicDNSyntax
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

func checkCIDRs(rep *Report, path string, list []string) {
	for i, s := range list {
		p := fmt.Sprintf("%s[%d]", path, i)
		if _, err := netip.ParsePrefix(s); err == nil {
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

// basicFilterSyntax is a structural stand-in for the RFC 4515 parser.
func basicFilterSyntax(s string) error {
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return fmt.Errorf("filter must be enclosed in parentheses")
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return fmt.Errorf("unbalanced parentheses")
			}
			if depth == 0 && i != len(s)-1 {
				return fmt.Errorf("filter must be a single expression")
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced parentheses")
	}
	if len(s) < 3 {
		return fmt.Errorf("empty filter")
	}
	return nil
}

// basicDNSyntax is a structural stand-in for the RFC 4514 parser.
func basicDNSyntax(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("empty DN")
	}
	for _, rdn := range splitUnescaped(s, ',') {
		for _, ava := range splitUnescaped(rdn, '+') {
			attr, _, ok := strings.Cut(ava, "=")
			if !ok || strings.TrimSpace(attr) == "" {
				return fmt.Errorf("%q is not attr=value", strings.TrimSpace(ava))
			}
		}
	}
	return nil
}

func splitUnescaped(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
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
}

// Validate checks the section on its own.
func (i *Intrusion) Validate() error { return sectionError(i.validate, "ids") }

func (i *Intrusion) validate(path string, rep *Report) {
	positive(rep, path+".summary_interval", i.SummaryInterval)
	positive(rep, path+".quiet_period", i.QuietPeriod)
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
	v.validateProfileCache(path, &p.Cache, rep)
	v.validateProfileLimits(path, &p.Limits, rep)
	p.Ratelimit.validate(path+".ratelimit", rep)
	v.checkFilter(rep, path+".shadow.filter", p.Shadow.Filter)
	v.checkDNList(rep, path+".shadow.bases", p.Shadow.Bases)
	if p.Record.Enabled && p.Record.File == "" {
		rep.errorf(path+".record.file", "required when record.enabled = true")
	}
}

func (v Validator) validateProfileListen(path string, p *Profile, rep *Report) {
	if len(p.Listen) == 0 {
		rep.errorf(path+".listen", "at least one listen address is required")
	}
	for i, addr := range p.Listen {
		checkListen(rep, fmt.Sprintf("%s.listen[%d]", path, i), addr)
	}
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
		if _, ok := c.Upstreams[p.Upstream]; !ok {
			rep.errorf(path+".upstream", "upstream %q is not defined", p.Upstream)
		}
	}
}

func (v Validator) validateProfileDirectory(path string, p *Profile, rep *Report) {
	if p.VirtualBase == "" {
		rep.errorf(path+".virtual_base", "required")
	} else {
		v.checkDN(rep, path+".virtual_base", p.VirtualBase)
	}
	v.checkDNList(rep, path+".bases", p.Bases)
	v.checkFilter(rep, path+".filter", p.Filter)
	v.checkFilter(rep, path+".exclude_filter", p.ExcludeFilter)
	for i, a := range p.Attrs.Allow {
		if t := strings.TrimSpace(a); t == "*" || t == "+" {
			rep.errorf(fmt.Sprintf("%s.attrs.allow[%d]", path, i), "'%s' is not allowed; list attributes explicitly", t)
		}
	}
	for k, tpl := range p.Attrs.Computed {
		if _, err := template.New(k).Parse(tpl); err != nil {
			rep.errorf(path+".attrs.computed."+k, "%v", err)
		}
	}
	if p.RDNAttr == "" {
		rep.errorf(path+".rdn_attr", "required")
	}
}

func (v Validator) validateProfileBind(path string, p *Profile, rep *Report) {
	cb := p.ClientBind
	if cb.DN != "" {
		v.checkDN(rep, path+".client_bind.dn", cb.DN)
	} else if cb.PasswordSource().IsSet() {
		rep.errorf(path+".client_bind.dn", "required when client_bind.password is set")
	}
	v.checkSecret(rep, path+".client_bind.password", cb.PasswordSource(), cb.DN != "")
	if p.AnonymousBind {
		rep.warnf(path+".anonymous_bind", "anonymous bind is enabled")
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
	}
	atLeast(rep, path+".limits.max_conns_per_ip", l.MaxConnsPerIP, 1)
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
	if t.MinVersion != nil {
		oneOf(rep, path+".min_version", *t.MinVersion, "1.2", "1.3")
	}
	if t.ClientAuth != nil {
		oneOf(rep, path+".client_auth", *t.ClientAuth, "none", "request", "require")
	}
	if t.Mode != nil && *t.Mode == "external" && (t.Cert == nil || t.Key == nil) {
		rep.errorf(path+".cert", "cert and key are required for mode = external")
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
	for _, name := range sortedKeys(c.Profiles) {
		p := c.Profiles[name]
		path := "profile." + name
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
		if !oneOf(rep, p+".type", c.Type, "telegram", "virola", "email", "webhook") {
			continue
		}
		switch c.Type {
		case "telegram":
			v.checkSecret(rep, p+".bot_token", c.BotTokenSource(), true)
			if c.ChatID == "" {
				rep.errorf(p+".chat_id", "required for type = telegram")
			}
			checkHTTPURL(rep, p+".api_base", c.APIBase)
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
	}
	if c.TLSInsecureSkipVerify {
		rep.warnf(p+".tls_insecure_skip_verify", "certificate verification is disabled")
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
}

func (v Validator) validateWebhookChannel(p string, c *Channel, rep *Report) {
	checkHTTPURL(rep, p+".url", c.URL)
	oneOf(rep, p+".method", c.Method, "POST", "PUT", "PATCH")
	if c.BodyTemplate != "" {
		if _, err := template.New("body").Parse(c.BodyTemplate); err != nil {
			rep.errorf(p+".body_template", "%v", err)
		}
	}
	v.checkSecret(rep, p+".hmac_secret", c.HMACSecretSource(), false)
	positive(rep, p+".timeout", c.Timeout)
	validateRetry(rep, p+".retry", c.Retry)
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
	}
	names := map[string]bool{}
	for i := range a.Tokens {
		p := fmt.Sprintf("%s.token[%d]", path, i)
		t := &a.Tokens[i]
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
	if ok && !isLoopbackHost(host) && !a.TLS.Builtin && a.TLS.Cert == "" {
		rep.errorf(path+".tls", "TLS is mandatory when listen is not loopback: set tls.builtin = true or tls.cert and tls.key")
	}
	if a.Metrics.Listen != "" {
		checkListen(rep, path+".metrics.listen", a.Metrics.Listen)
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
