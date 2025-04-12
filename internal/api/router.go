package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/logger"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

type APIServer struct {
	Port                  int
	logger                logger.Logger
	httpServer            *http.Server
	dbName                string
	pcapDirectory         string
	mongoClient           *mongo.Client
	userStore             *db.UserStore
	roleStore             *db.RoleStore
	serviceDetectionStore *db.ServiceStore
	pcapStore             *db.PCAPStore
}

func NewAPIServer(log logger.Logger) *APIServer {
	return &APIServer{
		Port:          4444,
		logger:        log,
		dbName:        "ad-shield",
		pcapDirectory: "/home/baiman/Desktop/pcap-store",
	}
}

func (a *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", "", a.Port)
	if err := a.ConnectToDB(); err != nil {
		fmt.Printf("error while connecting to database server")
		return err
	}

	router := mux.NewRouter()

	// ------------------USERS--------------------------
	router.HandleFunc("/api/v1/user/register", a.handleUserRegistration).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/users/all", a.handleGetAllRegisteredUsers).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/user/login", a.handleUserLogin).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/user/{id}", a.handleGetUserByID).Methods(http.MethodGet)

	// ------------------ROLES--------------------------
	router.HandleFunc("/api/v1/roles/add", a.handleAddRoles).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/roles", a.handleGetAllRoles).Methods(http.MethodGet)

	// --------------------------PORT-ANALYSIS---------------------
	router.HandleFunc("/api/v1/scan/port", a.HandlePortScan).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/scan/service", a.HandleServiceDetection).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/services", a.handleGetAllDetectedServices).Methods(http.MethodGet)

	// ---------------------PCAP-FILE-ANALYSIS------------------------
	router.HandleFunc("/api/v1/pcap/scan/{id}", a.handleAnalyzeOfPCAP).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/pcap/upload", a.handleUploadPCAPFile).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pcap/metas", a.handleGetAllPcapMetaData).Methods(http.MethodGet)

	// -----------------------AD-ROUTES-----------------------------------
	router.HandleFunc("/api/v1/ad/checkhealth", a.handleADHealthCheck).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/authenticate", a.handleADAuthentication).Methods(http.MethodPost)
	// ------------------AD-USER----------------------------------------------
	router.HandleFunc("/api/v1/ad/object/user/add", nil).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/users", a.handleGetAllUsers).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/user", a.handleUserByDN).Methods(http.MethodPost)

	// ----------------AD-GROUPS--------------------------------------------
	router.HandleFunc("/api/v1/ad/object/group/add", nil).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/groups", a.handleGetAllGroups).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/group", a.handleGetAGroup).Methods(http.MethodPost)

	// --------------------AD-OU---------------------------------------------
	router.HandleFunc("/api/v1/ad/object/ou/add", nil).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/ous", a.handleGetAllOU).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ad/object/ou", a.handleGetAOU).Methods(http.MethodPost)

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
		// write to file
		a.logger.Debug(fmt.Sprintf("Go request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path))
		// print to stdout
		log.Printf("Got request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) ConnectToDB() error {
	mongoURL := "mongodb://localhost:27018"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURL))
	if err != nil {
		fmt.Printf("error while connecting to mongodb server: %v \n", err)
		return err
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		fmt.Printf("unable to ping mongodb server: %v \n", err)
		return err
	}

	a.mongoClient = client
	a.userStore = db.NewUserStore(client, a.dbName)
	a.roleStore = db.NewRoleStore(client, a.dbName)
	a.serviceDetectionStore = db.NewServiceStore(client, a.dbName)
	a.pcapStore = db.NewPCAPStore(client, a.dbName)
	return nil
}

func responseWithJSON(
	w http.ResponseWriter,
	code int,
	docs interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(docs)
}
