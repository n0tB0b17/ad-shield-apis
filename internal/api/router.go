package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

type APIServer struct {
	Port        int
	logger      logger.Logger
	httpServer  *http.Server
	mongoURL    string
	mongoDBName string
	mongoClient *mongo.Client
}

func NewAPIServer(log logger.Logger) *APIServer {
	return &APIServer{
		Port:        4444,
		logger:      log,
		mongoURL:    "mongodb://localhost:27018",
		mongoDBName: "adshield",
	}
}

func (a *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", "", a.Port)

	if err := a.ConnectToDB(); err != nil {
		fmt.Printf("error while connecting to database server")
		return err
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/scan/port", a.HandlePortScan).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/service", a.HandleServiceDetection).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/pcap", a.handlePCAPFile).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/user/register", a.handleUserRegistration).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/user/login", nil).Methods(http.MethodPost)

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

func (a *APIServer) ConnectToDB() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(a.mongoURL))
	if err != nil {
		fmt.Printf("error while connecting to mongodb server: %v \n", err)
		return err
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		fmt.Printf("unable to ping mongodb server: %v \n", err)
		return err
	}

	a.mongoClient = client
	return nil
}
