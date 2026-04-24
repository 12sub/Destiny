package sysinfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// PrintNetworkProcesses lists active connections and the apps owning them
func PrintNetworkProcesses() {
	conns, _ := net.Connections("inet")

	fmt.Println("\n🌐 --- Active Network Processes & Threads ---")
	fmt.Printf("%-8s %-20s %-10s %-8s %s\n", "PROTO", "LOCAL", "PID", "THREADS", "APP NAME")
	fmt.Println("----------------------------------------------------------------------")

	for _, c := range conns {
		if c.Status == "LISTEN" || c.Status == "ESTABLISHED" {
			procName := "Unknown"
			threadCount := 0

			if c.Pid > 0 {
				p, err := process.NewProcess(c.Pid)
				if err == nil {
					procName, _ = p.Name()
					// Fetch thread count for the specific process
					threads, _ := p.NumThreads()
					threadCount = int(threads)
				}
			}

			local := fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
			proto := "TCP"
			if c.Type == 2 { proto = "UDP" }

			fmt.Printf("%-8s %-20s %-10d %-8d %s\n", proto, local, c.Pid, threadCount, procName)
		}
	}
}