package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bob17/adpis/internal/logger"
	"github.com/gorilla/mux"
)

type APIServer struct {
	Port       int
	logger     logger.Logger
	httpServer *http.Server
}

func NewAPIServer(log logger.Logger) *APIServer {
	return &APIServer{
		Port:   6969,
		logger: log,
	}
}

func (a *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", "", a.Port)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/scan/port", a.HandlePortScan).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/service", a.HandleServiceDetection).Methods(http.MethodPost)
	router.Use(a.Logger)

	a.httpServer = &http.Server{Addr: addr, Handler: router}
	return a.httpServer.ListenAndServe()
}

func (a *APIServer) Logger(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Go request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path)
		nxt.ServeHTTP(w, r)
	})
}
