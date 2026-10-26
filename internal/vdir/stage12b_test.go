package vdir

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/upstream"
)

// obsLog records what the directory hands to the detectors.
type obsLog struct {
	mu       sync.Mutex
	binds    []ids.BindObs
	searches []ids.SearchObs
}

func (o *obsLog) Bind(b ids.BindObs) { o.mu.Lock(); o.binds = append(o.binds, b); o.mu.Unlock() }
func (o *obsLog) Search(s ids.SearchObs) {
	o.mu.Lock()
	o.searches = append(o.searches, s)
	o.mu.Unlock()
}

// TestKnownSource_AllowCIDRs: binds and searches from the profile's
// ratelimit.allow_cidrs reach every detector but are marked KnownSource,
// so the masked-address detector does not count them (Stage 12b).
func TestKnownSource_AllowCIDRs(t *testing.T) {
	rl := config.Default().Ratelimit
	rl.AllowCIDRs = []string{"10.89.0.10/32"}
	guard, err := ratelimit.New(ratelimit.Options{Logger: slog.New(slog.DiscardHandler)}).Policy("virola", rl)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := profile.Compile("virola", baseProfile(), &config.Upstream{Kind: "ad"}, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	obs := &obsLog{}
	d := New(rules, &fakeUp{entries: []upstream.Entry{{DN: "CN=alice.adams,OU=Office,DC=test,DC=aldap", Attrs: map[string][]string{"sAMAccountName": {"alice.adams"}}}}}, Options{Logger: slog.New(slog.DiscardHandler), Events: &sink{}, Guard: guard, Observer: obs})
	for ip, want := range map[string]bool{"10.89.0.10": true, "10.89.0.11": false} {
		c := listener.NewConn("c-1", "virola", &net.TCPAddr{IP: net.ParseIP(ip), Port: 4000})
		d.Bind(context.Background(), c, "alice.adams", []byte("alice.adams-pass"))
		d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=alice.adams)"}, &collector{})
		obs.mu.Lock()
		b, s := obs.binds[len(obs.binds)-1], obs.searches[len(obs.searches)-1]
		obs.mu.Unlock()
		if b.IP != ip || b.KnownSource != want || s.IP != ip || s.KnownSource != want {
			t.Errorf("%s: bind %+v search known=%v, want known=%v", ip, b, s.KnownSource, want)
		}
	}
}
