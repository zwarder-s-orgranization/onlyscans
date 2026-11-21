package main

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// PromQL: orchestrator_queue_depth{plugin_id="scan.sast.kotlin"} (KEDA ScaledObject trigger).
	orchestratorQueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "orchestrator_queue_depth",
			Help: "Current number of queued/in-flight node tasks per plugin_id (KEDA autoscaling trigger).",
		},
		[]string{"plugin_id"},
	)

	// PromQL: sum by (status) (rate(orchestrator_runs_total[5m])).
	orchestratorRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "orchestrator_runs_total",
			Help: "Total number of workflow runs reaching a terminal status.",
		},
		[]string{"status"},
	)

	// PromQL: histogram_quantile(0.95, sum by (le, plugin_id) (rate(orchestrator_node_duration_seconds_bucket[5m]))).
	orchestratorNodeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "orchestrator_node_duration_seconds",
			Help:    "Node execution duration in seconds by plugin_id and terminal status.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"plugin_id", "status"},
	)

	// PromQL: orchestrator_active_workers{plugin_id="scan.sca"}.
	orchestratorActiveWorkers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "orchestrator_active_workers",
			Help: "Number of active non-draining workers connected per plugin_id.",
		},
		[]string{"plugin_id"},
	)
)

func init() {
	prometheus.MustRegister(
		orchestratorQueueDepth,
		orchestratorRunsTotal,
		orchestratorNodeDuration,
		orchestratorActiveWorkers,
	)
}

// trackQueuedTaskLocked records a queued/in-flight task and increments orchestrator_queue_depth.
// Caller must hold s.runMu.
func (s *Server) trackQueuedTaskLocked(nodeRunID, pluginID string) {
	if nodeRunID == "" || pluginID == "" {
		return
	}
	if s.trackedQueue == nil {
		s.trackedQueue = map[string]string{}
	}
	if _, exists := s.trackedQueue[nodeRunID]; exists {
		return
	}
	s.trackedQueue[nodeRunID] = pluginID
	orchestratorQueueDepth.WithLabelValues(pluginID).Inc()
}

// releaseQueuedTaskLocked decrements orchestrator_queue_depth when a tracked task settles or cancels.
// Caller must hold s.runMu.
func (s *Server) releaseQueuedTaskLocked(nodeRunID string) {
	if s.trackedQueue == nil || nodeRunID == "" {
		return
	}
	pluginID, ok := s.trackedQueue[nodeRunID]
	if !ok {
		return
	}
	delete(s.trackedQueue, nodeRunID)
	orchestratorQueueDepth.WithLabelValues(pluginID).Dec()
}

// releaseQueuedRunLocked releases all tracked tasks belonging to runID.
// Caller must hold s.runMu.
func (s *Server) releaseQueuedRunLocked(runID string) {
	if s.trackedQueue == nil || runID == "" {
		return
	}
	prefix := runID + ":"
	for nrID, pluginID := range s.trackedQueue {
		if strings.HasPrefix(nrID, prefix) {
			delete(s.trackedQueue, nrID)
			orchestratorQueueDepth.WithLabelValues(pluginID).Dec()
		}
	}
}

func (s *Server) recordRunTerminal(status string) {
	if status == "" {
		return
	}
	orchestratorRunsTotal.WithLabelValues(status).Inc()
}

func (s *Server) recordNodeDuration(pluginID, status string, d time.Duration) {
	if pluginID == "" || status == "" {
		return
	}
	orchestratorNodeDuration.WithLabelValues(pluginID, status).Observe(d.Seconds())
}

func (s *Server) setActiveWorkers(pluginID string, count int32) {
	if pluginID == "" {
		return
	}
	orchestratorActiveWorkers.WithLabelValues(pluginID).Set(float64(count))
}
