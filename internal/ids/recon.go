package ids

import (
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

// reconRepeat suppresses the same signature from one source for this long.
const reconRepeat = time.Minute

// Search feeds one client search to the recon and anomaly detectors.
func (e *Engine) Search(o SearchObs) {
	now := e.now()
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()
	e.masked.observe(cfg.ClientIPMasked, o.IP, o.Account, now)
	if cfg.Recon.Enabled {
		for _, sig := range Signatures(o) {
			if !e.reconAllowed(o.IP, sig, now) {
				continue
			}
			attrs := o.Attrs
			if attrs == nil {
				attrs = []string{}
			}
			e.ev.Emit(events.Event{Event: events.Recon, Level: events.LevelMedium, Profile: o.Profile, ConnID: o.ConnID, ClientIP: o.IP, Account: o.Account,
				Data: map[string]any{"signature": sig, "filter_norm": o.FilterNorm, "base": o.Base, "attrs": attrs}})
			e.log.Warn("recon signature", "signature", sig, "ip", o.IP, "profile", o.Profile, "base", o.Base)
			e.score(keyIP(o.IP), weightRecon, now)
		}
	}
	e.baselineObserve(o.Profile, o.IP, o.ConnID, o.Base, o.FilterNorm, o.Attrs, now, false)
}

func (e *Engine) reconAllowed(ip, sig string, now time.Time) bool {
	if ip == "" {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.src(ip)
	s.lastSeen = now
	if last, ok := s.lastRecon[sig]; ok && now.Sub(last) < reconRepeat {
		return false
	}
	s.lastRecon[sig] = now
	return true
}

// searchShape is what the recon signatures look at.
type searchShape struct {
	attrs, filterAttrs map[string]bool
	presentAll         bool // (objectClass=*)
	broad              bool // every entry matches (present filter or none)
}

func shapeOf(o SearchObs) searchShape {
	sh := searchShape{attrs: map[string]bool{}, filterAttrs: map[string]bool{}}
	for _, a := range o.Attrs {
		sh.attrs[strings.ToLower(strings.SplitN(a, ";", 2)[0])] = true
	}
	if o.Filter != nil {
		ldapfilter.Walk(o.Filter, func(n *ldapfilter.Filter) bool {
			if n.Attr != "" {
				sh.filterAttrs[strings.ToLower(strings.SplitN(n.Attr, ";", 2)[0])] = true
			}
			if n.Kind == ldapfilter.Present && strings.EqualFold(n.Attr, "objectClass") {
				sh.presentAll = true
			}
			return true
		})
	}
	if !sh.presentAll && strings.EqualFold(strings.TrimSpace(o.FilterNorm), "(objectclass=*)") {
		sh.presentAll = true
	}
	sh.broad = sh.presentAll || o.Filter == nil || o.Filter.Kind == ldapfilter.Present
	return sh
}

// mentions reports whether the attribute is requested or filtered on.
func (sh searchShape) mentions(names ...string) bool {
	for _, n := range names {
		if sh.attrs[n] || sh.filterAttrs[n] {
			return true
		}
	}
	return false
}

// anyPrefix reports whether an attribute with the prefix is requested or filtered on.
func (sh searchShape) anyPrefix(prefix string) bool {
	for _, m := range []map[string]bool{sh.attrs, sh.filterAttrs} {
		for a := range m {
			if strings.HasPrefix(a, prefix) {
				return true
			}
		}
	}
	return false
}

// Signatures returns the recon signatures a search matches (SPEC §3.4).
func Signatures(o SearchObs) []string {
	sh := shapeOf(o)
	var out []string
	if sh.presentAll && o.Scope == "sub" && (o.BaseKind == "virtual" || o.BaseKind == "rootdse" || o.Base == "") {
		out = append(out, SigRootDump)
	}
	for _, sig := range []struct {
		name  string
		match bool
	}{
		{SigSDDump, sh.mentions("ntsecuritydescriptor")},
		{SigSIDHistory, sh.mentions("sidhistory")},
		{SigTrusts, sh.mentions("trustpartner", "trusteddomain", "trustdirection")},
		{SigMSDS, sh.anyPrefix("msds-")},
		{SigAdminCount, sh.mentions("admincount")},
		{SigSPNSweep, sh.attrs["serviceprincipalname"] && o.Scope == "sub" && (sh.broad || sh.filterAttrs["serviceprincipalname"])},
		{SigBaseOutside, o.BaseKind == "outside"},
	} {
		if sig.match {
			out = append(out, sig.name)
		}
	}
	return out
}
