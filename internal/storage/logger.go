package storage

import (
	"net"
	"os"
	"fmt"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"destiny/pkg/models"
)

// LogToDebugFile appends packet info to custom .dbg file
func LogToDebugFile(packetChan <-chan models.PacketInfo, filename string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	for p := range packetChan {
		// If process info is missing, try to find it
		if p.Processes == "" {
			p.PID, p.Processes = findProcessByPort(p.Source)
		}

		line := fmt.Sprintf("[%s] %s | Proc: %s (PID:%d) | %s -> %s | %s\n",
			p.Timestamp, p.Protocol, p.Processes, p.PID, p.Source, p.Dest, p.Info)

		file.WriteString(line)
	}
}

func findProcessByPort(sourceStr string) (int32, string) {
	_, portStr, err := net.SplitHostPort(sourceStr)
	if err != nil {
		return 0, ""
	}

	// FIX: Use psnet (gopsutil) instead of standard net
	conns, err := psnet.Connections("inet")
	if err != nil {
		return 0, ""
	}

	for _, c := range conns {
		if fmt.Sprintf("%d", c.Laddr.Port) == portStr {
			p, err := process.NewProcess(c.Pid)
			if err == nil {
				name, _ := p.Name()
				return c.Pid, name
			}
		}
	}
	return 0, ""
}