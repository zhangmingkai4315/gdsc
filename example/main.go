package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func handerPacket(packet gopacket.Packet) {
	dnslayer := packet.Layer(layers.LayerTypeDNS)
	if dnslayer != nil {
		fmt.Printf("%v", dnslayer.LayerContents())
	}
}

func main() {
	handler, err := pcap.OpenLive("en1", 1500, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handler.SetBPFFilter("udp and port 53")
	if err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		handerPacket(packet)
	}
}
