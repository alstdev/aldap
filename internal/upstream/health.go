package upstream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// healthLoop checks s every health_interval and whenever requestCheck fires.
func (u *Upstream) healthLoop(ctx context.Context, s *server) {
	interval := time.Duration(u.cfg.HealthInterval)
	if interval <= 0 {
		interval = 10 * time.Second
	}
	u.healthCheck(ctx, s)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		u.healthCheck(ctx, s)
		s.svc.reap()
		s.bind.reap()
	}
}

// healthCheck runs one probe on a fresh connection and records the result.
func (u *Upstream) healthCheck(ctx context.Context, s *server) {
	start := u.now()
	err := u.probe(ctx, s.url, u.cfg.HealthCheck)
	if ctx.Err() != nil {
		return
	}
	u.observe(s, err == nil, err, u.now().Sub(start))
}

// probe performs one health check of the given kind: rootdse (anonymous
// read of the root DSE), bind (service bind) or search (bind plus a
// base-scope search of base_dn).
func (u *Upstream) probe(ctx context.Context, srv ServerURL, kind string) error {
	budget := time.Duration(u.cfg.Timeouts.Connect + u.cfg.Timeouts.Bind + u.cfg.Timeouts.Search)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	c, err := u.dial(ctx, srv)
	if err != nil {
		return err
	}
	defer closeQuietly(c, u.log)
	switch kind {
	case "bind", "search":
		if u.cfg.BindDN != "" {
			c.SetTimeout(time.Duration(u.cfg.Timeouts.Bind))
			if err := c.Bind(u.cfg.BindDN, u.password); err != nil {
				return fmt.Errorf("service bind: %w", err)
			}
		}
		if kind == "bind" {
			return nil
		}
		c.SetTimeout(time.Duration(u.cfg.Timeouts.Search))
		_, err := c.Search(ldap.NewSearchRequest(u.cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, PresentAll, []string{"1.1"}, nil))
		if err != nil {
			return fmt.Errorf("search %s: %w", u.cfg.BaseDN, err)
		}
		return nil
	default:
		if u.cfg.BindDN != "" {
			// The service bind is part of the probe: a directory that
			// answers the anonymous root DSE but refuses the service bind
			// (LDAP signing required on plain ldap://) is down for ALDAP.
			c.SetTimeout(time.Duration(u.cfg.Timeouts.Bind))
			if err := c.Bind(u.cfg.BindDN, u.password); err != nil {
				return fmt.Errorf("service bind: %w", err)
			}
		}
		c.SetTimeout(time.Duration(u.cfg.Timeouts.Search))
		res, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, PresentAll, []string{"defaultNamingContext", "namingContexts"}, nil))
		if err != nil {
			return fmt.Errorf("rootdse: %w", err)
		}
		if res == nil || len(res.Entries) == 0 {
			return errors.New("rootdse: empty response")
		}
		return nil
	}
}
