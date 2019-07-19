package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/google/gopacket/layers"
	"github.com/zhangmingkai4315/gdsc/core"
)

const (
	// VERSION current software version
	VERSION = "0.1"
)

func main() {
	iface := flag.String("i", "", "the network interface to collect packet")
	port := flag.String("p", "53", "dns listen port")
	protocal := flag.String("P", "udp", "tcp or udp protocal")
	metricHost := flag.String("http.host", "0.0.0.0:11011", "metrics server http port")
	metricsPath := flag.String("http.path", "/metrics", "metrics server url path")
	version := flag.Bool("v", false, "print current gdsc version")

	flag.Parse()

	if *version == true {
		fmt.Printf("gdsc version : %s\n", VERSION)
		return
	}

	config, err := core.NewConfig(
		*iface,
		*protocal,
		*port,
		*metricHost,
		*metricsPath,
	)
	if err != nil {
		log.Printf("%s\n", err.Error())
		os.Exit(1)
	}
	app, err := core.NewApp(config)
	if err != nil {
		log.Printf("%s\n", err.Error())
		os.Exit(1)
	}
	app.Start()
}
