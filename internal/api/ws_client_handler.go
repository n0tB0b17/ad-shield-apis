package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/bob17/adpis/internal/searchsploit"
	"github.com/bob17/adpis/internal/vulners"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ConnectionType string
type ScanTypeReq string

const (
	VULNERS_REQ      ScanTypeReq = "vs"
	SEARCHSPLOIT_REQ ScanTypeReq = "st"
	BOTH_REQ         ScanTypeReq = "both"

	PING_REQ            ConnectionType = "ping"
	SCAN_REQ            ConnectionType = "scan"
	VS_HEALTH_CHECK_REQ ConnectionType = "vs_health_check"
	ST_HEALTH_CHECK_REQ ConnectionType = "st_health_check"
)

type Message struct {
	Type     ConnectionType `json:"type"`
	JWTToken string         `json:"jwt_token"`
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
	wg   sync.WaitGroup
}

var WsClients = struct {
	sync.RWMutex
	m map[string]*WSClient
}{m: make(map[string]*WSClient)}

func (c *WSClient) readPump(ss *db.ServiceStore) {
	defer func() {
		fmt.Println("Client disconnected")
		c.wg.Wait()

		WsClients.Lock()
		delete(WsClients.m, c.Meta.ID)
		WsClients.Unlock()

		close(c.Send)
		if err := c.Conn.Close(); err != nil {
			if !errors.Is(err, net.ErrClosed) {

			}
		}
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
			} else {
				fmt.Printf("Client: %s read error: %v \n", c.Meta.ID, err)
			}
			break
		}

		c.wg.Add(1)
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
	c.wg.Done()

	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		fmt.Printf("error while decoding message: %v \n", err)
		c.sendResponse("failed", "invalid message type", "provide proper message type", "")
		return
	}

	_, err := rbac.DecodeToken(msg.JWTToken)
	if err != nil {
		c.sendResponse(
			"failed",
			"invalid jwt token provided",
			err.Error(),
			"",
		)
		return
	}

	switch msg.Type {
	case SCAN_REQ:
		c.handleMessage(msg.Payload, a)
	case PING_REQ:
		c.sendResponse("success", "PONG request", "Connection is alive, go ahead and scan for vulnerabilities", "")
	case VS_HEALTH_CHECK_REQ:
		c.handleVSHealthCheck()
	case ST_HEALTH_CHECK_REQ:
		c.handleSTHealthCheck()
	default:
		c.sendResponse("failed", "invalid-type", "retry again with proper type", "")
	}
}

func (c *WSClient) handleVSHealthCheck() {
	vs := vulners.GetVulners(3)
	isRunning, err := vs.HealthCheck()
	if err != nil {
		c.sendResponse("failed", "internal error while checking vulners API", err.Error(), "")
		return
	}

	if !isRunning {
		c.sendResponse("failed", "vulners API not running", "make a manual test to check if vulners API is running", "")
		return
	}

	c.sendResponse("success", "vulners API is running", "go ahead and make request to scan for vulnerability", "")
}

func (c *WSClient) handleSTHealthCheck() {
	isRunning, err := searchsploit.HealthCheck()
	if err != nil {
		c.sendResponse("failed", "internal error while checking for searchsploit", err.Error(), "")
		return
	}

	if !isRunning {
		c.sendResponse("failed", "searchsploit not available", "server don't have searchsploit installed", "")
		return
	}

	c.sendResponse("success", "searchsploit is available", "go ahead and make request to scan for vulnerabilities", "")
}

func (c *WSClient) handleMessage(payload ScanPayload, a *db.ServiceStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := bson.ObjectIDFromHex(payload.PortScannerID)
	if err != nil {
		c.sendResponse(
			"failed",
			"invalid service_id",
			"invalid service id provided, try with proper clientID",
			"",
		)

		return
	}

	portInfo, err := a.GetDetectedServiceByID(ctx, id)
	if err != nil {
		c.sendResponse(
			"failed",
			"service not found",
			err.Error(),
			"",
		)
		return
	}

	switch payload.WhichScan {
	case VULNERS_REQ:
		c.scan("vs", portInfo.ScanDetail)
	case SEARCHSPLOIT_REQ:
		c.scan("st", portInfo.ScanDetail)
	case BOTH_REQ:
		c.scan("both", portInfo.ScanDetail)
	default:
		c.sendResponse("failed", "invalid scan type", "retry with proper scan type", portInfo)
	}
}

func (c *WSClient) scan(t ScanTypeReq, ports []db.ServiceResult) {
	for _, port := range ports {
		if t == "vs" {
			vuln := vulners.GetVulners(3)
			resp, err := vuln.Query(port.Service, port.Version)
			if err != nil {
				c.sendResponse(
					"failed",
					"unable to query vulners API",
					err.Error(),
					"",
				)
				return
			}

			c.sendResponse(
				"success",
				"vulnerability scanned with vulners",
				fmt.Sprintf("scanned vulnerabilities for: %s", port.Service),
				resp,
			)
		} else if t == "st" {
			resp, err := searchsploit.Query(port.Service, port.Version)
			if err != nil {
				c.sendResponse(
					"failed",
					"unable to query searchsploit API",
					err.Error(),
					"",
				)
				return
			}

			c.sendResponse(
				"success",
				"vulnerability scanned with searchsploit",
				fmt.Sprintf("scanned vulnerabilities for: %s", port.Service),
				resp,
			)
		} else if t == "both" {
			c.sendResponse(
				"success",
				"both scan detected",
				"for now, both scan is under-construction, it will be up in season release",
				"",
			)
		}
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
		// WsClients.Lock()
		// delete(WsClients.m, c.Meta.ID)
		// WsClients.Unlock()
		// close(c.Send)
		fmt.Printf("Client buffer is full, deleting client: %s \n", c.Meta.IPAddr)
	}
}
