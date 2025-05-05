package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ConnectionType string
type ScanTypeReq string

const (
	VULNERS_REQ      ScanTypeReq = "vs"
	SEARCHSPLOIT_REQ ScanTypeReq = "st"
	BOTH_REQ         ScanTypeReq = "both"

	PING_REQ ConnectionType = "ping"
	SCAN_REQ ConnectionType = "scan"
)

type Message struct {
	Type     ConnectionType `json:"type"`
	ClientID string         `json:"client_id"`
	UserID   string         `json:"user_id"`
	JWTToken string         `json:"jwt_token,omitempty"`
	Payload  ScanPayload    `json:"payload,omitempty"`
}

type ScanPayload struct {
	PortScannerID string      `json:"ports_id"`
	WhichScan     ScanTypeReq `json:"which_scan"`
}

type ClientMetaData struct {
	ID          string    `json:"id"`
	IPAddr      string    `json:"ip_addr"`
	UserAgent   string    `json:"user_agent"`
	ConnectedAt time.Time `json:"connected_at"`
}

type WSClient struct {
	Conn *websocket.Conn
	Meta ClientMetaData
	Send chan []byte
	Mu   sync.Mutex
}

var WsClients = struct {
	sync.RWMutex
	m map[string]*WSClient
}{m: make(map[string]*WSClient)}

func (c *WSClient) readPump(ss *db.ServiceStore) {
	defer func() {
		fmt.Println("Client disconnected")
		WsClients.Lock()
		delete(WsClients.m, c.Meta.ID)
		WsClients.Unlock()
		c.Conn.Close()
		close(c.Send)
	}()

	c.Conn.SetReadLimit(MaxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(PongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, msg, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
			) {
				fmt.Printf("unexpected close error: %v \n", err)
			}
			break
		}

		go c.processMessage(msg, ss)
	}
}

func (c *WSClient) writePump() {
	newTicker := time.NewTicker(PingPeriod)
	defer func() {
		newTicker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.Mu.Lock()
			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				c.Mu.Unlock()
				return
			}

			w.Write(msg)

			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				c.Mu.Unlock()
				return
			}

			c.Mu.Unlock()
		case <-newTicker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			c.Mu.Lock()
			if err := c.Conn.WriteMessage(websocket.PongMessage, nil); err != nil {
				c.Mu.Unlock()
				return
			}

			c.Mu.Unlock()
		}
	}
}

func (c *WSClient) processMessage(message []byte, a *db.ServiceStore) {
	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		fmt.Printf("error while decoding message: %v \n", err)
		c.sendResponse("failed", "invalid message type", "provide proper message type", "")
		return
	}

	switch msg.Type {
	case SCAN_REQ:
		c.handleMessage(msg.Payload, a)
	case PING_REQ:
		c.sendResponse("success", "PONG", "pongggg", "")
	default:
		c.sendResponse("failed", "invalid-type", "retry again with proper type", "")
	}
}

func (c *WSClient) handleMessage(payload ScanPayload, a *db.ServiceStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, _ := bson.ObjectIDFromHex(payload.PortScannerID)
	_, err := a.GetDetectedServiceByID(ctx, id)
	if err != nil {
		return
	}

	switch payload.WhichScan {
	case VULNERS_REQ:
		// vulners.GetVulners(3)
		c.sendResponse("success", "vulners API making", "xxxx", "")
	case SEARCHSPLOIT_REQ:
		// searchsploit.Query()
		c.sendResponse("success", "searchsploit API making", "xxxx", "")
	case BOTH_REQ:
		c.sendResponse("success", "both type request", "xxxxx", "")
	default:
		c.sendResponse("failed", "invalid scan type", "retry with proper scan type", "")
	}
}

func (c *WSClient) sendResponse(status, message, description string, resp interface{}) {
	clientResp := map[string]interface{}{
		"message":     message,
		"status":      status,
		"description": description,
		"resp":        resp,
	}

	by, err := json.Marshal(clientResp)
	if err != nil {
		fmt.Println("error while encoding json response...")
		return
	}

	select {
	case c.Send <- by:
	default:
		WsClients.Lock()
		delete(WsClients.m, c.Meta.ID)
		WsClients.Unlock()
		close(c.Send)
		fmt.Printf("Client buffer is full, deleting client: %s \n", c.Meta.IPAddr)
	}
}
