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
	"destiny/pkg/models"
)

var (
	iface []string
	proxyActive bool
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
		Short: "Scan the network for available devices",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cidr := args[0]
			
			// 1. Get the list of IPs to scan
			targetIPs, err := scanner.GetIPsFromCIDR(cidr)
			if err != nil {
				fmt.Printf("Error parsing CIDR: %v\n", err)
				return
			}
		targetIface := "eno1"
		if len(iface) > 0 {
			targetIface = iface[0]
		}

			// 2. Open PCAP Handle
			handle, err := pcap.OpenLive(targetIface, 65536, true, pcap.BlockForever)
			if err != nil {
				fmt.Printf("Error opening interface: %v\n", err)
				return
			}
			defer handle.Close()

			fmt.Printf("🚀 Scanning %d IPs on %s...\n", len(targetIPs), targetIface)

			// 3. Start a Listener Goroutine for ARP Replies
			go func() {
				source := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range source.Packets() {
					if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
						arp := arpLayer.(*layers.ARP)
						if arp.Operation == layers.ARPReply {
							fmt.Printf("[+] Found: %s (%s)\n", 
								net.IP(arp.SourceProtAddress), 
								net.HardwareAddr(arp.SourceHwAddress))
						}
					}
				}
			}()

			// 4. Send Requests (Need your local IP/MAC for the 'Source' fields)
			// For brevity, ensure you replace these with your actual local details
			myIP := net.ParseIP("192.168.5.17") 
			myMAC, _ := net.ParseMAC("00:11:22:33:44:55")

			for _, target := range targetIPs {
				scanner.SendARPRequest(handle, myMAC, myIP, target)
			}
			
			// Give the listener time to catch final replies
			time.Sleep(2 * time.Second)
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

	monitorCmd.Flags().StringSliceVarP(&iface, "interface", "i", []string{"eno1"}, "Network interfaces to monitor")
	monitorCmd.Flags().BoolVarP(&proxyActive, "proxy", "x", false, "Start the transparent proxy alongside monitoring")

	// network interface for scanning
	scanCmd.Flags().StringSliceVarP(&iface, "interface", "i", []string{"eno1"}, "Network interface to use for scanning")
	rootCmd.AddCommand(monitorCmd)

	rootCmd.AddCommand(scanCmd)

	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(netstatCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}