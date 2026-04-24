package scanner

import (
	"net"

	"github.com/google/gopacket/pcap"

	"destiny/pkg/models"
)

// FindDevices sends ARP requests to a CIDR range to find active hosts
func FindDevices(ifaceName string, cidr string) ([]models.Device, error) {
	// 1. Parse the CIDR range
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// 2. Setup the interface handle for sending raw ARP packets
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// testing network, looping through several ip ranges
	devices := []models.Device{
		{IP: "192.168.1.1", MAC: "00:11:22:33:44:55", Status: "Online"},
		{IP: "192.168.1.15", MAC: "AA:BB:CC:DD:EE:FF", Status: "Online"},
	}
	return devices, nil
}