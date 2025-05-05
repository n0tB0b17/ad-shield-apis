package api

import (
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
	WriteWait      time.Duration = 55 * time.Second
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
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "Unable to upgrade connection to socket",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	a.logger.Debug(fmt.Sprintf("New client connected from: %s \n", conn.RemoteAddr().String()))
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

	wsClient.sendResponse(
		"success",
		"welcome to ws server",
		"try vulnerability scanning with two of our different services",
		"",
	)

	go wsClient.readPump(a.serviceDetectionStore)
	go wsClient.writePump()
}
