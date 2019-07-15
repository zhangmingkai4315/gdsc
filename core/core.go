package core

import (
	"log"
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
	requestTypeSummary  cmap.ConcurrentMap
}

func newStatistics() *statistics {
	return &statistics{
		responseCodeSummary: cmap.New(),
		requestTypeSummary:  cmap.New(),
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
				dnslayer := packet.Layer(layers.LayerTypeDNS)
				if dnslayer != nil {
					dns := dnslayer.(*layers.DNS)
					app.counterPackets(dns)
				}
			}
			wg.Done()
		}(packetSource)
	}
	wg.Wait()
}

func (app *App) counterPackets(dnspacket *layers.DNS) {
	var info *statistics
	if dnspacket.QR == false {
		// request dns packet
		info = app.queryInfo

	} else {
		info = app.responseInfo
	}

	requestType := info.requestTypeSummary
	queryType := dnspacket.Questions[0].Type.String()
	if tmp, ok := requestType.Get(queryType); ok {
		requestType.Set(queryType, int64(1)+tmp.(int64))
	} else {
		requestType.Set(queryType, int64(1))
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
