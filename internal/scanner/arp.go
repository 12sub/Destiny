package scanner

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SendARPRequest crafts and sends a single ARP packet.
// The 'error' at the end of the line below fixes the "too many return values" issue.
func SendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	// 1. Define the Ethernet Layer (Broadcast)
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// 2. Define the ARP Layer
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4, // CORRECTED: This field is named 'Protocol'
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// 3. Serialize the packet into bytes
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true, 
		ComputeChecksums: true,
	}
	
	if err := gopacket.SerializeLayers(buffer, opts, eth, arp); err != nil {
		return err // Supported by the 'error' return in function signature
	}

	// 4. Write the raw bytes to the network interface
	return handle.WritePacketData(buffer.Bytes())
}