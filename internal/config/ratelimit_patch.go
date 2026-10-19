package config

// With returns r with the set keys of p applied ([profile.<name>.ratelimit]
// overrides any key of [ratelimit]).
func (r Ratelimit) With(p RatelimitPatch) Ratelimit {
	setBool := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setInt := func(dst *int, src *int) {
		if src != nil {
			*dst = *src
		}
	}
	setDur := func(dst *Duration, src *Duration) {
		if src != nil {
			*dst = *src
		}
	}
	setStr := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	setList := func(dst *[]string, src *[]string) {
		if src != nil {
			*dst = append([]string(nil), (*src)...)
		}
	}
	setBool(&r.Enabled, p.Enabled)
	setDur(&r.NegativeCacheTTL, p.NegativeCacheTTL)
	setBool(&r.ConstantTimeBindFail, p.ConstantTimeBindFail)
	setStr(&r.LockResponse, p.LockResponse)
	setList(&r.AllowCIDRs, p.AllowCIDRs)
	setList(&r.AllowAccounts, p.AllowAccounts)
	setInt(&r.IP.MaxFailures, p.IP.MaxFailures)
	setDur(&r.IP.Window, p.IP.Window)
	setDur(&r.IP.LockDuration, p.IP.LockDuration)
	setInt(&r.IP.BindRPS, p.IP.BindRPS)
	setInt(&r.IP.BindBurst, p.IP.BindBurst)
	setInt(&r.IP.SearchRPS, p.IP.SearchRPS)
	setInt(&r.IP.SearchBurst, p.IP.SearchBurst)
	setInt(&r.Account.MaxFailures, p.Account.MaxFailures)
	setDur(&r.Account.Window, p.Account.Window)
	setDur(&r.Account.LockDuration, p.Account.LockDuration)
	setDur(&r.Delay.Base, p.Delay.Base)
	setDur(&r.Delay.Max, p.Delay.Max)
	setBool(&r.Tarpit.Enabled, p.Tarpit.Enabled)
	setDur(&r.Tarpit.Delay, p.Tarpit.Delay)
	setInt(&r.Tarpit.MaxConns, p.Tarpit.MaxConns)
	setBool(&r.Lockdown.Auto, p.Lockdown.Auto)
	setList(&r.Lockdown.AllowCIDRs, p.Lockdown.AllowCIDRs)
	setList(&r.Lockdown.AllowAccounts, p.Lockdown.AllowAccounts)
	return r
}
