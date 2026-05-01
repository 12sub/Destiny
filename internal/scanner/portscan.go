package scanner

import (
	"bufio"
	"fmt"
	"sync"
	"net"
	"time"
)

// ScanPorts checks a list of common ports and grabs service banners
func ScanPorts(ip string, timeout time.Duration) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Common ports to check for APIs and Web Services
	ports := []int{80, 443, 8080, 8443, 3000, 5000, 22}

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
				conn.Close()
			}
		}(port)
	}
	wg.Wait()
	return openPorts
}
func grabSSHBanner(conn net.Conn) {
	// Set a deadline so we don't hang if the server is shy
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	fmt.Printf("    |-> SSH Fingerprint: %s", banner)
}