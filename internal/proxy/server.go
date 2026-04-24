package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
	"fmt"

	"destiny/pkg/models"
)

type ProxyServer struct {
	Addr string
	Out  chan<- models.PacketInfo
}

func (p *ProxyServer) Start() {
	server := &http.Server{
		Addr: p.Addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Report the traffic to Destiny
			p.reportTraffic(r)

			if r.Method == http.MethodConnect {
				handleTunnel(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}
	log.Printf("[!] Destiny Proxy listening on %s", p.Addr)
	log.Fatal(server.ListenAndServe())
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, _ := hijacker.Hijack()
	go io.Copy(dest_conn, client_conn)
	go io.Copy(client_conn, dest_conn)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *ProxyServer) reportTraffic(r *http.Request) {
	info := fmt.Sprintf("%s %s%s", r.Method, r.Host, r.URL.Path)
	// Send to the same channel the sniffer uses
	p.Out <- models.NewPacketInfo(r.RemoteAddr, r.Host, "HTTP-PROXY", info)
}