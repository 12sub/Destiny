package scanner

import (
	"net"
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