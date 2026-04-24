package sysinfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// PrintHostInfo gathers and display local machine specs
func PrintHostInfo() {
	h, _ := host.Info()
	v, _ := mem.VirtualMemory()
	c, _ := cpu.Info()

	fmt.Println("\n ---- Local System Information ---")
	fmt.Printf("OS: %v (%v)\n", h.OS, h.PlatformFamily)
	fmt.Printf("Platform Version: %v\n", h.PlatformVersion)
	fmt.Printf("Hostname: %v\n", h.Hostname)

	if len(c) > 0 {
		fmt.Printf("CPU: %v (Cores: %v)\n", c[0].ModelName, h.Procs)
	}

	// Convet bytes to Gigabytes
	totalRAM := float64(v.Total) / (1024 * 1024 * 1024)
	usedRAM := float64(v.Used) / (1024 * 1024 * 1024)
	fmt.Printf("RAM: %.2f GB Total / %.2f GB Used\n", totalRAM, usedRAM)
}