package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bob17/adpis/internal/logger"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type APIServer struct {
	Port       int
	logger     logger.Logger
	httpServer *http.Server
}

func NewAPIServer(log logger.Logger) *APIServer {
	return &APIServer{
		Port:   4444,
		logger: log,
	}
}

func (a *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", "", a.Port)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/scan/port", a.HandlePortScan).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/service", a.HandleServiceDetection).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/pcap", a.handlePCAPFile).Methods(http.MethodPost)
	router.Use(a.Logger)

	corsOptions := cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Content-Length", "Application-Encoding"},
	}
	c := cors.New(corsOptions)

	handler := c.Handler(router)
	a.httpServer = &http.Server{Addr: addr, Handler: handler}
	return a.httpServer.ListenAndServe()
}

func (a *APIServer) Logger(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Go request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path)
		nxt.ServeHTTP(w, r)
	})
}
