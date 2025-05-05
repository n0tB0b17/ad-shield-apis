package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var (
	ReadBuffSize  int = 1024
	WriteBuffSize int = 1024

	PongWait       time.Duration = 60 * time.Second
	PingPeriod     time.Duration = (PongWait * 9) / 10
	WriteWait      time.Duration = 30 * time.Second
	MaxMessageSize int64         = 512 * 1024
)

var Upgrader = websocket.Upgrader{
	ReadBufferSize:  ReadBuffSize,
	WriteBufferSize: WriteBuffSize,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (a *APIServer) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("error while upgrading websocket connection: %v \n", err)
		return
	}

	fmt.Printf("New client connected from: %s \n", conn.RemoteAddr().String())
	md := ClientMetaData{
		ID:          uuid.New().String(),
		IPAddr:      conn.RemoteAddr().String(),
		UserAgent:   r.UserAgent(),
		ConnectedAt: time.Now(),
	}

	wsClient := &WSClient{
		Conn: conn,
		Meta: md,
		Send: make(chan []byte, 256),
	}

	WsClients.Lock()
	WsClients.m[md.ID] = wsClient
	WsClients.Unlock()

	resp := map[string]interface{}{
		"message":     "welcome to ws server",
		"description": "try vulnerability scanning with two of our different services",
		"status":      "success",
	}

	respBy, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("error while parsing response interface...")
		return
	}

	wsClient.Mu.Lock()
	err = wsClient.Conn.WriteMessage(websocket.TextMessage, respBy)
	wsClient.Mu.Unlock()

	if err != nil {
		fmt.Println("error while writing welcome message to client")
		return
	}

	go wsClient.readPump(a.serviceDetectionStore)
	go wsClient.writePump()
}
