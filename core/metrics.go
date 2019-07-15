package core

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metricsCollector struct {
	queryTypeMetric *prometheus.Desc
	info            *statistics
	queryOrResponse bool
}

func newMetricsCollector(info *statistics, qr bool) *metricsCollector {
	describe := "response"
	if qr == false {
		describe = "query"
	}
	return &metricsCollector{
		queryTypeMetric: prometheus.NewDesc(
			"dns_query_type",
			"dns query type counter",
			[]string{"type"},
			prometheus.Labels{"qr": describe},
		),
		info:            info,
		queryOrResponse: qr,
	}
}

func (collector *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	//Update this section with the each metric you create for a given collector
	ch <- collector.queryTypeMetric
}

func (collector *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	for item := range collector.info.requestTypeSummary.Iter() {
		ch <- prometheus.MustNewConstMetric(
			collector.queryTypeMetric,
			prometheus.CounterValue,
			float64(item.Val.(int64)),
			item.Key,
		)
	}

}

func (app *App) startMetricsServer(
	queryInfo, responseInfo *statistics) {
	log.Printf("start web metric server in %s%s", app.config.metricsHost, app.config.metricsPath)
	queryCollector := newMetricsCollector(queryInfo, false)
	responseCollector := newMetricsCollector(responseInfo, true)

	prometheus.MustRegister(queryCollector)
	prometheus.MustRegister(responseCollector)

	http.Handle(app.config.metricsPath, promhttp.Handler())
	http.ListenAndServe(app.config.metricsHost, nil)
}
