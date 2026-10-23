// Package api serves the management API (SPEC §7, docs/openapi.yaml) on the
// TCP listener ([api]), the IPC socket for aldapctl (no token, scope admin)
// and the Prometheus endpoint. The data come from the process-wide models:
// the event bus (events, SSE), the rate limiter (locks, lockdown), the
// detectors (indicators, baseline) and the metrics registry; everything that
// depends on the current configuration is reached through a Backend.
package api
