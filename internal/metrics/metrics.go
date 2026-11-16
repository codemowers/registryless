package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Received   *prometheus.CounterVec
	Duplicates *prometheus.CounterVec
	Missing    *prometheus.CounterVec
	Expected   *prometheus.CounterVec
	Repair     *prometheus.CounterVec
	Dropped    *prometheus.CounterVec
	Transfers  *prometheus.CounterVec
}

func New(r prometheus.Registerer) *Metrics {
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "registryless_receive_" + name, Help: help}, labels)
		r.MustRegister(c)
		return c
	}
	return &Metrics{
		Received:   counter("multicast_bytes_total", "Unique valid multicast payload bytes received, including reordered data.", "project_namespace"),
		Duplicates: counter("duplicate_bytes_total", "Duplicate multicast payload bytes received.", "project_namespace"),
		Missing:    counter("missing_bytes_total", "Expected payload bytes not observed before the reorder window closed; measured per announced transfer.", "project_namespace"),
		Expected:   counter("expected_bytes_total", "Expected payload bytes for receive transfers whose reorder window closed.", "project_namespace"),
		Repair:     counter("http_repair_bytes_total", "Bytes downloaded over HTTP to complete multicast transfers.", "project_namespace"),
		Dropped:    counter("dropped_packets_total", "Authenticated transfer packets dropped locally due to bounded queue or reorder buffer capacity.", "project_namespace"),
		Transfers:  counter("transfers_total", "Receive transfers by outcome (complete, repaired, failed, already_present).", "project_namespace", "outcome"),
	}
}
