package cmd

import (
	"github.com/spf13/cobra"

	"destiny/internal/proxy"
	"destiny/internal/storage"
	"destiny/pkg/models"
)

var proxyPort string

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().StringVarP(&proxyPort, "port", "p", "8081", "Port to run the proxy server on")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a proxy server to capture web traffic",
	Run: func(cmd *cobra.Command, args []string) {
		packetChan := make(chan models.PacketInfo, 100)

		// Start the logger so proxy traffic is saved to .dbg
		go storage.LogToDebugFile(packetChan, "proxy_capture.dbg")

		// Start the Proxy
		p := &proxy.ProxyServer{
			Addr: ":" + proxyPort,
			Out:  packetChan,
		}
		
		p.Start()
	},
}