package scanner

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

// ScanPorts checks a list of common ports and grabs service banners
func ScanPorts(ip string) {
	commonPorts := []int{21, 22, 53, 80, 443}
	
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		
		if err == nil {
			fmt.Printf("[+] Port %d is OPEN\n", port)
			
			// Feature: SSH Fingerprinting 
			if port == 22 {
				grabSSHBanner(conn)
			}
			conn.Close()
		}
	}
}

func grabSSHBanner(conn net.Conn) {
	// Set a deadline so we don't hang if the server is shy
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	fmt.Printf("    |-> SSH Fingerprint: %s", banner)
}