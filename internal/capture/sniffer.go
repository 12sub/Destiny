package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"destiny/pkg/models"
)

// we will write 2 functions
// Function 1 will start sniffing packets. we will call this StartSniffer
// Function 2 will process each packets sent to the network, we will call this processPacket
// we will also setup channels for each functions for concurrncy

func StartSniffer(device string, outChan chan<- models.PacketInfo) {
	handle, err := pcap.OpenLive(device, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Filter for ICMP and DNS (UDP Port 53) [cite: 18, 34]
	if err := handle.SetBPFFilter("icmp or udp port 53"); err != nil {
		log.Fatal(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		processPacket(packet, outChan)
	}
}

func processPacket(packet gopacket.Packet, outChan chan<- models.PacketInfo) {
	var srcIP, dstIP, proto, info string

	// Get IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
	}

	// Parse ICMP [cite: 33]
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		proto = "ICMP"
		info = fmt.Sprintf("Type: %d, Code: %d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}

	// Parse DNS [cite: 33]
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		proto = "DNS"
		if len(dns.Questions) > 0 {
			info = fmt.Sprintf("Query: %s", string(dns.Questions[0].Name))
		}
	}

	if proto != "" {
		outChan <- models.NewPacketInfo(srcIP, dstIP, proto, info)
	}

}