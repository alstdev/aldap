// Package metrics registers the Prometheus metrics of SPEC §11 (prefix
// aldap_). A Metrics value is created once per process and handed to the
// packages that observe traffic; nil receivers are safe so tests and tools
// can run without a registry.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// Metrics holds every collector of the process.
type Metrics struct {
	reg *prometheus.Registry

	ConnectionsActive    *prometheus.GaugeVec
	BindsTotal           *prometheus.CounterVec
	BindDuration         *prometheus.HistogramVec
	SearchesTotal        *prometheus.CounterVec
	SearchResults        *prometheus.HistogramVec
	ProfileCost          *prometheus.HistogramVec
	UpstreamQueriesTotal *prometheus.CounterVec
	UpstreamLatency      *prometheus.HistogramVec
	UpstreamUp           *prometheus.GaugeVec
	LocksActive          *prometheus.GaugeVec
	AttackActive         *prometheus.GaugeVec
	EventsTotal          *prometheus.CounterVec
	EventsDroppedTotal   *prometheus.CounterVec
	NotifyTotal          *prometheus.CounterVec
	CacheEntries         *prometheus.GaugeVec
	ReplicaAge           *prometheus.GaugeVec
	CertExpiry           *prometheus.GaugeVec
	BuildInfo            *prometheus.GaugeVec
}

// New creates a registry with every metric registered; version, commit and
// date fill aldap_build_info.
func New(version, commit, date string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}
	m.ConnectionsActive = gauge("connections_active", "Open client connections.", "profile")
	m.BindsTotal = counter("binds_total", "Bind requests by result.", "profile", "result")
	m.BindDuration = histogram("bind_duration_seconds", "Bind latency as seen by the client.", []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}, "profile")
	m.SearchesTotal = counter("searches_total", "Search requests by cache outcome.", "profile", "cache")
	m.SearchResults = histogram("search_results", "Entries returned per search.", []float64{0, 1, 5, 10, 50, 100, 500, 1000, 5000}, "profile")
	m.ProfileCost = histogram("profile_cost", "Upstream queries per client request.", []float64{0, 1, 2, 3, 5, 10, 20, 50}, "profile")
	m.UpstreamQueriesTotal = counter("upstream_queries_total", "Upstream operations by result.", "upstream", "server", "op", "result")
	m.UpstreamLatency = histogram("upstream_latency_seconds", "Upstream operation latency.", []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}, "upstream", "server", "op")
	m.UpstreamUp = gauge("upstream_up", "1 when the server is up.", "upstream", "server")
	m.LocksActive = gauge("locks_active", "Active locks by target.", "target")
	m.AttackActive = gauge("attack_active", "1 while an attack of the kind is active.", "kind")
	m.EventsTotal = counter("events_total", "Events emitted by type.", "event")
	m.EventsDroppedTotal = counter("events_dropped_total", "Events dropped per sink.", "sink")
	m.NotifyTotal = counter("notify_total", "Notifications by channel and result.", "channel", "result")
	m.CacheEntries = gauge("cache_entries", "Cached entries per profile.", "profile")
	m.ReplicaAge = gauge("replica_age_seconds", "Age of the replica per profile.", "profile")
	m.CertExpiry = gauge("cert_expiry_seconds", "Seconds until the listener certificate expires.", "listener")
	m.BuildInfo = gauge("build_info", "Build information.", "version", "commit", "date")
	m.BuildInfo.WithLabelValues(version, commit, date).Set(1)
	for _, c := range []prometheus.Collector{m.ConnectionsActive, m.BindsTotal, m.BindDuration, m.SearchesTotal, m.SearchResults, m.ProfileCost,
		m.UpstreamQueriesTotal, m.UpstreamLatency, m.UpstreamUp, m.LocksActive, m.AttackActive, m.EventsTotal, m.EventsDroppedTotal, m.NotifyTotal,
		m.CacheEntries, m.ReplicaAge, m.CertExpiry, m.BuildInfo,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})} {
		reg.MustRegister(c)
	}
	return m
}

func gauge(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "aldap", Name: name, Help: help}, labels)
}

func counter(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "aldap", Name: name, Help: help}, labels)
}

func histogram(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "aldap", Name: name, Help: help, Buckets: buckets}, labels)
}

// Registry returns the registry (for /metrics and tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Gather returns the current metric families.
func (m *Metrics) Gather() ([]*dto.MetricFamily, error) { return m.reg.Gather() }

// The methods below are nil-safe so callers need no checks.

// Bind records one bind outcome.
func (m *Metrics) Bind(profile, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.BindsTotal.WithLabelValues(profile, result).Inc()
	m.BindDuration.WithLabelValues(profile).Observe(d.Seconds())
}

// Search records one search: cache outcome, results and upstream cost.
func (m *Metrics) Search(profile, cache string, results, upstreamQueries int) {
	if m == nil {
		return
	}
	m.SearchesTotal.WithLabelValues(profile, cache).Inc()
	m.SearchResults.WithLabelValues(profile).Observe(float64(results))
	m.ProfileCost.WithLabelValues(profile).Observe(float64(upstreamQueries))
}

// Connection tracks an opened (+1) or closed (-1) client connection.
func (m *Metrics) Connection(profile string, delta float64) {
	if m == nil {
		return
	}
	m.ConnectionsActive.WithLabelValues(profile).Add(delta)
}

// Upstream records one upstream operation.
func (m *Metrics) Upstream(upstream, server, op, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.UpstreamQueriesTotal.WithLabelValues(upstream, server, op, result).Inc()
	m.UpstreamLatency.WithLabelValues(upstream, server, op).Observe(d.Seconds())
}

// SetUpstreamUp publishes the state of one server.
func (m *Metrics) SetUpstreamUp(upstream, server string, up bool) {
	if m == nil {
		return
	}
	v := 0.0
	if up {
		v = 1
	}
	m.UpstreamUp.WithLabelValues(upstream, server).Set(v)
}

// Event counts an emitted event.
func (m *Metrics) Event(kind string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(kind).Inc()
}

// Dropped counts events dropped by a sink.
func (m *Metrics) Dropped(sink string, n float64) {
	if m == nil || n <= 0 {
		return
	}
	m.EventsDroppedTotal.WithLabelValues(sink).Add(n)
}

// SetLocks publishes the number of active locks per target.
func (m *Metrics) SetLocks(ip, account int) {
	if m == nil {
		return
	}
	m.LocksActive.WithLabelValues("ip").Set(float64(ip))
	m.LocksActive.WithLabelValues("account").Set(float64(account))
}

// SetAttack publishes whether an attack kind is active.
func (m *Metrics) SetAttack(kind string, active bool) {
	if m == nil {
		return
	}
	v := 0.0
	if active {
		v = 1
	}
	m.AttackActive.WithLabelValues(kind).Set(v)
}

// SetCertExpiry publishes the seconds left on a listener certificate.
func (m *Metrics) SetCertExpiry(listener string, notAfter time.Time) {
	if m == nil {
		return
	}
	m.CertExpiry.WithLabelValues(listener).Set(time.Until(notAfter).Seconds())
}

// Notify counts one notification outcome of a channel.
func (m *Metrics) Notify(channel, result string) {
	if m == nil {
		return
	}
	m.NotifyTotal.WithLabelValues(channel, result).Inc()
}
