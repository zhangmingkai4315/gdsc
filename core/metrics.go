package core

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define the query or response const
const (
	Query    = false
	Response = true
)

type metricsCollector struct {
	dnsTypeMetric         *prometheus.Desc
	dnsCounterMetric      *prometheus.Desc
	dnsResponseCodeMetric *prometheus.Desc
	dnsOpCodeMetric       *prometheus.Desc
	dnsIPMetric           *prometheus.Desc
	info                  *statistics
	qr                    bool
}

func newMetricsCollector(info *statistics, qr bool) *metricsCollector {
	describe := "response"
	if qr == Query {
		describe = "query"
	}
	return &metricsCollector{
		dnsTypeMetric: prometheus.NewDesc(
			"dns_type_total",
			"dns query or response type counter",
			[]string{"type"},
			prometheus.Labels{"qr": describe},
		),
		dnsOpCodeMetric: prometheus.NewDesc(
			"dns_op_code_total",
			"dns op code counter",
			[]string{"code"},
			prometheus.Labels{"qr": describe},
		),
		dnsResponseCodeMetric: prometheus.NewDesc(
			"dns_response_code_total",
			"dns response code counter",
			[]string{"code"},
			prometheus.Labels{"qr": describe},
		),
		dnsCounterMetric: prometheus.NewDesc(
			"dns_packet_total",
			"dns packet counter",
			nil,
			prometheus.Labels{"qr": describe},
		),
		dnsIPMetric: prometheus.NewDesc(
			"dns_packet_ip_total",
			"dns packet ip counter",
			[]string{"ip", "for"},
			prometheus.Labels{"qr": describe},
		),
		info: info,
		qr:   qr,
	}
}

func (collector *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	//Update this section with the each metric you create for a given collector
	ch <- collector.dnsTypeMetric
	ch <- collector.dnsCounterMetric
	ch <- collector.dnsResponseCodeMetric
	ch <- collector.dnsOpCodeMetric
	ch <- collector.dnsIPMetric
}

func (collector *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	totalCounter := float64(0)
	for item := range collector.info.typeSummary.Iter() {
		eachTypeCounter := float64(item.Val.(int64))
		ch <- prometheus.MustNewConstMetric(
			collector.dnsTypeMetric,
			prometheus.CounterValue,
			eachTypeCounter,
			item.Key,
		)
		totalCounter += eachTypeCounter
	}
	ch <- prometheus.MustNewConstMetric(
		collector.dnsCounterMetric,
		prometheus.CounterValue,
		totalCounter,
	)
	if collector.qr == Response {
		for item := range collector.info.responseCodeSummary.Iter() {
			eachTypeCounter := float64(item.Val.(int64))
			ch <- prometheus.MustNewConstMetric(
				collector.dnsResponseCodeMetric,
				prometheus.CounterValue,
				eachTypeCounter,
				item.Key,
			)
		}
	}
	if collector.qr == Query {
		for item := range collector.info.opCodeSummary.Iter() {
			eachTypeCounter := float64(item.Val.(int64))
			ch <- prometheus.MustNewConstMetric(
				collector.dnsOpCodeMetric,
				prometheus.CounterValue,
				eachTypeCounter,
				item.Key,
			)
		}

	}

	for item := range collector.info.ipSrcSummary.Iter() {
		eachIPCounter := float64(item.Val.(int64))
		ch <- prometheus.MustNewConstMetric(
			collector.dnsIPMetric,
			prometheus.CounterValue,
			eachIPCounter,
			item.Key,
			"src",
		)
	}

	for item := range collector.info.ipDstSummary.Iter() {
		eachIPCounter := float64(item.Val.(int64))
		ch <- prometheus.MustNewConstMetric(
			collector.dnsIPMetric,
			prometheus.CounterValue,
			eachIPCounter,
			item.Key,
			"dst",
		)
	}

}

func (app *App) startMetricsServer(
	queryInfo, responseInfo *statistics) {
	log.Printf("start web metric server in %s%s", app.config.metricsHost, app.config.metricsPath)
	queryCollector := newMetricsCollector(queryInfo, Query)
	responseCollector := newMetricsCollector(responseInfo, Response)

	prometheus.MustRegister(queryCollector)
	prometheus.MustRegister(responseCollector)

	http.Handle(app.config.metricsPath, promhttp.Handler())
	http.ListenAndServe(app.config.metricsHost, nil)
}
