package config

import (
	"testing"
	"time"
)

func TestRatelimit_With(t *testing.T) {
	base := Default().Ratelimit
	if got := base.With(RatelimitPatch{}); got.IP.MaxFailures != 20 || got.LockResponse != "invalidCredentials" || got.Account.MaxFailures != 3 {
		t.Fatalf("empty patch changed values: %+v", got)
	}
	f, d, s, b, l := 7, Duration(time.Minute), "busy", true, []string{"10.0.0.0/8"}
	p := RatelimitPatch{Enabled: &b, NegativeCacheTTL: &d, ConstantTimeBindFail: &b, LockResponse: &s, AllowCIDRs: &l, AllowAccounts: &l,
		IP:      IPPatch{MaxFailures: &f, Window: &d, LockDuration: &d, BindRPS: &f, BindBurst: &f, SearchRPS: &f, SearchBurst: &f},
		Account: AccountPatch{MaxFailures: &f, Window: &d, LockDuration: &d}, Delay: DelayPatch{Base: &d, Max: &d},
		Tarpit: TarpitPatch{Enabled: &b, Delay: &d, MaxConns: &f}, Lockdown: LockdownPatch{Auto: &b, AllowCIDRs: &l, AllowAccounts: &l}}
	got := base.With(p)
	if got.IP.MaxFailures != 7 || got.IP.Window != d || got.IP.BindBurst != 7 || got.IP.SearchRPS != 7 || got.Account.MaxFailures != 7 ||
		got.Account.LockDuration != d || got.Delay.Max != d || got.LockResponse != "busy" || !got.Tarpit.Enabled || got.Tarpit.MaxConns != 7 ||
		!got.Lockdown.Auto || len(got.Lockdown.AllowCIDRs) != 1 || len(got.AllowAccounts) != 1 || got.NegativeCacheTTL != d {
		t.Errorf("patch not applied: %+v", got)
	}
	l[0] = "changed"
	if got.AllowCIDRs[0] == "changed" {
		t.Error("list aliased")
	}
	if base.IP.MaxFailures != 20 {
		t.Error("base mutated")
	}
}
