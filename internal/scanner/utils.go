package scanner

import (
	"net"
	"fmt"
)

// GetIPsFromCIDR returns a slice of all IPs in a given CIDR range.
func GetIPsFromCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		// Create a copy of the IP to avoid overwriting the same memory
		tempIP := make(net.IP, len(ip))
		copy(tempIP, ip)
		ips = append(ips, tempIP)
	}

	// Remove network and broadcast addresses for a cleaner scan
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// inc increments an IP address.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetInterfaceDetails detects the local IP and MAC for a given interface name (e.g., "eth0", "eno1")
func GetInterfaceDetails(ifaceName string) (net.IP, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s not found: %v", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		// Look for IPv4 address
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, iface.HardwareAddr, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no active IPv4 address found on interface %s", ifaceName)
}

// internal/scanner/network.go

// GetAutoInterface searches for the first active, non-loopback IPv4 interface.
func GetAutoInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// Skip if interface is down or is a loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Check for an IPv4 address
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					// Found an active interface with an IP!
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no active network interface discovered")
}