package main

// This is the entry point. this is also the place that prints ASCII and handles CLI arguments

import (
	"fmt"
	"os"
	"net"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/spf13/cobra"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"destiny/internal/capture"
	"destiny/internal/storage"
	"destiny/internal/scanner"
	"destiny/internal/web"
	"destiny/internal/auth"
	"destiny/internal/proxy"
	"destiny/internal/sysinfo"
	"destiny/internal/fuzz"
	"destiny/pkg/models"
)

var (
	iface []string
	proxyActive bool
	fuzzTarget   string
	fuzzWordlist string
	fuzzMode     string
	threads      int
)

func main() {
	var rootCmd = &cobra.Command{
		Use:	"Destiny",
		Short:	"Destiny Network Analyzer",
		PersistentPreRun: func(cmd *cobra.Command, args []string){
			figure.NewFigure("Destiny", "", true).Print() 
			fmt.Println("\n-- Network Monitoring System --")
		},
	}

	var monitorCmd = &cobra.Command{
		Use: "monitor",
		Short: "Start ICMP and DNS monitoring",
		Run: func(cmd *cobra.Command, args []string) {
			packetChan := make(chan models.PacketInfo, 100)

			// Launch a sniffer for every interfaces provided
			for _, ifaces := range iface {
				go func(i string) {
					fmt.Printf("[+] Starting sniffer on: %s\n", i)
					capture.StartSniffer(i, packetChan)
				}(ifaces)
			}

			// start web server
			go web.StartWebServer("8080", packetChan)

			// Start Logger Consumer [cite: 20]
			go storage.LogToDebugFile(packetChan, "capture.dbg")

			// Start if proxy flag is set
			if proxyActive {
				p := &proxy.ProxyServer{Addr: ":8888", Out: packetChan}
				go p.Start()
				fmt.Println(" [+] Destiny proxy active on port 8888")
			}

			// blocks the mai thread to keeping running goroutines 
			select {}

			// Start CLI Display Consumer [cite: 22]
			go func() {
				for p := range packetChan {
					fmt.Printf("[%s] %s: %s -> %s | %s\n", p.Protocol, p.Timestamp, p.Source, p.Dest, p.Info)
				}
			}()

			// Inside monitorCmd Run block
			go storage.LogToJSON(packetChan, "logs/capture.dbg")

			// // Start Sniffer Producer [cite: 17]
			// for _, i := range iface{
			// 	go func(ifaceName string) {
			// 		fmt.Printf("Monitoring on %s...\n", ifaceName)
			// 		capture.StartSniffer(ifaceName, packetChan)
			// 	}(i)
			// }
			
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan [cidr]",
		Short: "Scan the network and identify open ports",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cidr := args[0]
			targetIface, _ := cmd.Flags().GetString("interface")

			// Safety Check: If flag is empty, default to a common one or eno1
			if targetIface == "" {
				fmt.Println("🔍 No interface specified. Searching for active interface...")
				discovered, err := scanner.GetAutoInterface()
				if err != nil {
					fmt.Printf("❌ Discovery Failed: %v\n", err)
					return
				}
				targetIface = discovered
				fmt.Printf("✅ Discovered interface: %s\n", targetIface) // Or whatever your primary interface is
				}

			// 1. DYNAMICALLY get your local IP and MAC
			myIP, myMAC, err := scanner.GetInterfaceDetails(targetIface)
			if err != nil {
				fmt.Printf("❌ Error detecting interface details: %v\n", err)
				return
			}

			targetIPs, _ := scanner.GetIPsFromCIDR(cidr)
			handle, _ := pcap.OpenLive(targetIface, 65536, true, pcap.BlockForever)
			defer handle.Close()

			fmt.Printf("🚀 Interface: %s | Local IP: %s | Local MAC: %s\n", targetIface, myIP, myMAC)

			// 2. Listener for ARP Replies + Chained Port Scan
			go func() {
				source := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range source.Packets() {
					if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
						arp := arpLayer.(*layers.ARP)
						if arp.Operation == layers.ARPReply {
							hostIP := net.IP(arp.SourceProtAddress).String()
							fmt.Printf("\n[+] Host Found: %s (%s)\n", hostIP, net.HardwareAddr(arp.SourceHwAddress))
							
							// CHAIN: If host found, scan common ports
							fmt.Printf("    🔍 Scanning ports for %s...\n", hostIP)
							open := scanner.ScanPorts(hostIP, 500*time.Millisecond)
							if len(open) > 0 {
								fmt.Printf("    🔓 Open Ports: %v\n", open)
							}
						}
					}
				}
			}()

			// 3. Send Requests using the dynamic local details
			for _, target := range targetIPs {
				scanner.SendARPRequest(handle, myMAC, myIP, target)
			}
			
			time.Sleep(3 * time.Second)
		},
	}
	var sshCmd = &cobra.Command{
		Use:   "gen-ssh [name]",
		Short: "Generate a new SSH ED25519 key pair",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := auth.GenerateSSHKeyPair(args[0])
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("✅ Keys generated: %s.key and %s.pub\n", args[0], args[0])
			}
		},
	}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Display local system hardware and OS information",
		Run: func(cmd *cobra.Command, args []string) {
			sysinfo.PrintHostInfo()
		},
	}

	var netstatCmd = &cobra.Command{
		Use:   "netstat",
		Short: "Display active network connections and their associated processes",
		Run: func(cmd *cobra.Command, args []string) {
			sysinfo.PrintNetworkProcesses()
		},
	}

	var fuzzCmd = &cobra.Command{
		Use:   "fuzz",
		Short: "Locate subdirectories, APIs, and file structures",
		Run: func(cmd *cobra.Command, args []string) {
			// Use default wordlist if none provided
			// For a NOC tool, you'd usually load this from a file
			commonPaths := []string{"admin", "api", "v1", "v2", "config", "backup", "index.php", ".env", "swagger.json"}
			
			fmt.Printf("🎯 Starting %s discovery on %s...\n", fuzzMode, fuzzTarget)
			fuzz.StartFuzzer(fuzzTarget, commonPaths, threads, fuzzMode)
		},
	}

	// command flags for fuzzing
	fuzzCmd.Flags().StringVarP(&fuzzTarget, "target", "t", "", "Target IP or Domain (required)")
	fuzzCmd.Flags().StringVarP(&fuzzMode, "mode", "m", "all", "Discovery mode: dir, api, file, all")
	fuzzCmd.Flags().IntVarP(&threads, "threads", "n", 10, "Number of concurrent workers")
	fuzzCmd.MarkFlagRequired("target")

	monitorCmd.Flags().StringSliceVarP(&iface, "interface", "i", []string{"eno1"}, "Network interfaces to monitor")
	monitorCmd.Flags().BoolVarP(&proxyActive, "proxy", "x", false, "Start the transparent proxy alongside monitoring")

	// network interface for scanning
	scanCmd.Flags().StringSliceVarP(&iface, "interface", "i", []string{"eno1"}, "Network interface to use for scanning")
	rootCmd.AddCommand(monitorCmd)

	rootCmd.AddCommand(scanCmd)

	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(netstatCmd)
	rootCmd.AddCommand(fuzzCmd)

	

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}