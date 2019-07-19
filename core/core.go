package core

import (
	"log"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map"
)

// Max define the max workers for statistics job
const (
	MaxWorker = 5
)

//App define a app manager
type App struct {
	worker       int
	config       *Config
	handler      *pcap.Handle
	input        chan gopacket.Packet
	queryInfo    *statistics
	responseInfo *statistics
}

type statistics struct {
	responseCodeSummary cmap.ConcurrentMap
	typeSummary         cmap.ConcurrentMap
	opCodeSummary       cmap.ConcurrentMap
	ipSrcSummary        cmap.ConcurrentMap
	ipDstSummary        cmap.ConcurrentMap
	dnsSizeSummary      cmap.ConcurrentMap
}

func newStatistics() *statistics {
	return &statistics{
		responseCodeSummary: cmap.New(),
		typeSummary:         cmap.New(),
		opCodeSummary:       cmap.New(),
		ipSrcSummary:        cmap.New(),
		ipDstSummary:        cmap.New(),
	}
}

// NewApp create a new App Manager
func NewApp(config *Config) (*App, error) {
	log.Printf("init packets collection from interface %s", config.iface)
	handler, err := pcap.OpenLive(config.iface, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	log.Printf("set pcap filter to \"%s\"", config.GetBPFString())
	err = handler.SetBPFFilter(config.GetBPFString())
	if err != nil {
		return nil, err
	}
	app := &App{
		worker:       MaxWorker,
		config:       config,
		handler:      handler,
		input:        make(chan gopacket.Packet),
		responseInfo: newStatistics(),
		queryInfo:    newStatistics(),
	}
	return app, nil
}

func (app *App) collectPacket() {
	packetSource := gopacket.NewPacketSource(app.handler, app.handler.LinkType())
	var wg sync.WaitGroup
	for i := 0; i < MaxWorker; i++ {
		wg.Add(1)
		go func(*gopacket.PacketSource) {
			for packet := range packetSource.Packets() {
				qr := true
				dnslayer := packet.Layer(layers.LayerTypeDNS)
				if dnslayer != nil {
					dns := dnslayer.(*layers.DNS)
					app.counterDNSPackets(dns)
					qr = dns.QR
				}
				ipv4layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4layer != nil {
					ip := ipv4layer.(*layers.IPv4)
					app.counterIPv4Packets(ip, qr)
				}

			}
			wg.Done()
		}(packetSource)
	}
	wg.Wait()
}

func ipv4To16net(ip string) string {
	return strings.Join(strings.Split(ip, ".")[0:3], ".") + ".0"
}

func (app *App) counterIPv4Packets(ipv4packet *layers.IPv4, queryResonseCode bool) {
	info := app.queryInfo
	if queryResonseCode == Response {
		info = app.responseInfo
	}
	app.countIPv4(info.ipSrcSummary, ipv4To16net(ipv4packet.SrcIP.String()))
	app.countIPv4(info.ipDstSummary, ipv4To16net(ipv4packet.DstIP.String()))
}

func (app *App) countIPv4(ipSummary cmap.ConcurrentMap, ip string) {
	if tmp, ok := ipSummary.Get(ip); ok {
		ipSummary.Set(ip, int64(1)+tmp.(int64))
	} else {
		ipSummary.Set(ip, int64(1))
	}
}

func (app *App) counterDNSPackets(dnspacket *layers.DNS) {
	var info *statistics
	if dnspacket.QR == Query {
		info = app.queryInfo
		app.countOpCode(info.opCodeSummary, dnspacket)
		app.counterDNSPacketSize(info.dnsSizeSummary, dnspacket.Contents)
	} else {
		info = app.responseInfo
		app.countResponseCode(info.responseCodeSummary, dnspacket)
	}
	app.countType(info.typeSummary, dnspacket)
}

// count all packets of dns type
func (app *App) countType(typeSummary cmap.ConcurrentMap, dnspacket *layers.DNS) {
	queryType := dnspacket.Questions[0].Type.String()
	if tmp, ok := typeSummary.Get(queryType); ok {
		typeSummary.Set(queryType, int64(1)+tmp.(int64))
	} else {
		typeSummary.Set(queryType, int64(1))
	}
}

func (app *App) countOpCode(typeSummary cmap.ConcurrentMap, dnspacket *layers.DNS) {
	opCode := dnspacket.OpCode.String()
	if tmp, ok := typeSummary.Get(opCode); ok {
		typeSummary.Set(opCode, int64(1)+tmp.(int64))
	} else {
		typeSummary.Set(opCode, int64(1))
	}
}

func (app *App) countResponseCode(typeSummary cmap.ConcurrentMap, dnspacket *layers.DNS) {
	responseCode := dnspacket.ResponseCode.String()
	if tmp, ok := typeSummary.Get(responseCode); ok {
		typeSummary.Set(responseCode, int64(1)+tmp.(int64))
	} else {
		typeSummary.Set(responseCode, int64(1))
	}
}

// Start a loop to collect and anylze
func (app *App) Start() {

	// create a web server
	go app.startMetricsServer(app.queryInfo, app.responseInfo)
	// start collect packet in block mode
	app.collectPacket()

}

// Stop the manager
func (app *App) Stop() {
	app.handler.Close()
}
