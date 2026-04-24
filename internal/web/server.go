package web

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"

	"destiny/pkg/models"
)

// Hub maintains the set of active clients and broadcasts messages to them
type Hub struct {
	Clients   map[*websocket.Conn]bool
	Broadcast chan models.PacketInfo
}

func StartWebServer(port string, packetChan chan models.PacketInfo) {
	app := fiber.New()
	hub := &Hub{
		Clients:   make(map[*websocket.Conn]bool),
		Broadcast: packetChan, // Reuse the channel from our sniffer [cite: 16]
	}

	// Serve Static Files (Frontend)
	app.Static("/", "./internal/web/ui")

	// API: Get history from .dbg file 
	app.Get("/api/logs", func(c *fiber.Ctx) error {
		return c.SendFile("capture.dbg")
	})

	// WebSocket: Real-time stream [cite: 43]
	app.Get("/ws/live", websocket.New(func(c *websocket.Conn) {
		hub.Clients[c] = true
		defer func() {
			delete(hub.Clients, c)
			c.Close()
		}()

		for {
			// Keep connection alive
			if _, _, err := c.ReadMessage(); err != nil {
				break
			}
		}
	}))

	// Broadcast Loop: Listen for packets and push to all connected browsers
	go func() {
		for packet := range hub.Broadcast {
			for client := range hub.Clients {
				if err := client.WriteJSON(packet); err != nil {
					log.Printf("WS error: %v", err)
					client.Close()
					delete(hub.Clients, client)
				}
			}
		}
	}()

	log.Fatal(app.Listen(":" + port))
}