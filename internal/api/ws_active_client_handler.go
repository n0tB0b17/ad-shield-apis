package api

// func (s *APIServer) handleGetAllActiveWSConnection(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet {
// 		return
// 	}

// 	wsClients := getConnectedClients()
// 	fmt.Println(wsClients)
// }

// func getConnectedClients() []ClientMetaData {
// 	WsClients.RLock()
// 	defer WsClients.RUnlock()

// 	wsClients := make([]ClientMetaData, 0, len(WsClients.m))
// 	for _, ws := range WsClients.m {
// 		wsClients = append(wsClients, ws.Meta)
// 	}

// 	return wsClients
// }
