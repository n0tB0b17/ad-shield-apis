package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
	clientStore           *db.ClientStore
	userActivityStore     *db.UserActivityStore
	ipLookupStore         *db.LookupStore
}

func NewAPIServer(log logger.Logger) *APIServer {
	pcapStore := os.Getenv("PCAP_STORE")
	return &APIServer{
		Port:          4444,
		logger:        log,
		dbName:        "",
		pcapDirectory: pcapStore,
	}
}

func (a *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", "", a.Port)
	if err := a.ConnectToDB(); err != nil {
		fmt.Printf("error while connecting to database server")
		return err
	}

	router := mux.NewRouter()
	router.Use(a.Logger)
	superAdminRoute := router.PathPrefix("/api/v1").Subrouter()

	clientRoute := router.PathPrefix("/api/v1/{client_id}").Subrouter()
	clientRoute.Use(a.ValidateIfRealClientID, a.InitializeStores)

	protectedRoute := router.PathPrefix("/api/v1/{client_id}").Subrouter()
	protectedRoute.Use(a.ValidateIfRealClientID, a.InitializeStores, a.Authorization)
	protectedRoute.Use(a.validateClientWithGivenToken, a.validateIfUserExistInClient, a.validateForPermissions)

	// --------------SUPER-ADMIN---------------------------------
	superAdminRoute.HandleFunc("/add/client", a.handleClientAdd).Methods(http.MethodPost)
	superAdminRoute.HandleFunc("/clients", a.handleGetAllClient).Methods(http.MethodGet)
	superAdminRoute.HandleFunc("/client/{id}", a.handleGetClient).Methods(http.MethodGet)
	superAdminRoute.HandleFunc("/client/{id}/delete", a.handleDeleteClient).Methods(http.MethodDelete)
	superAdminRoute.HandleFunc("/client/{id}/update", a.handleUpdateClient).Methods(http.MethodPut)
	superAdminRoute.HandleFunc("/clients/stats", a.handleGenerateBasicAnalysis).Methods(http.MethodGet)

	superAdminRoute.HandleFunc("/clients/{id}/pcaps", a.handleBasicAnalysisPCAP).Methods(http.MethodGet)
	superAdminRoute.HandleFunc("/clients/{id}/pcaps/stats", a.handleGetClientPCAPStats).Methods(http.MethodGet)

	superAdminRoute.HandleFunc("/clients/{id}/lookups", a.handleBasicAnalysisIPLookup).Methods(http.MethodGet) // get iplookup with clientID
	superAdminRoute.HandleFunc("/clients/{id}/lookups/stats", a.handleGetIPLookupStats).Methods(http.MethodGet)

	superAdminRoute.HandleFunc("/clients/{id}/services", a.handleBasicAnalysisServiceDetection).Methods(http.MethodGet) // get services with clientID
	superAdminRoute.HandleFunc("/clients/{id}/services/stats", a.handleGetAllStatsFromService).Methods(http.MethodGet)  // get services's stats with clientID

	superAdminRoute.HandleFunc("/clients/{id}/users", a.handleBasicAnalysisUsers).Methods(http.MethodGet)
	superAdminRoute.HandleFunc("/clients/{id}/users/stats", a.handleGetAllStatsFromUsers).Methods(http.MethodGet)

	superAdminRoute.HandleFunc("/clients/{id}/roles", a.handleBasicAnalysisRoles).Methods(http.MethodGet)
	superAdminRoute.HandleFunc("/clients/{id}/roles/stats", a.handleGetAllStatsFromRoles).Methods(http.MethodGet)

	// ------------------USERS--------------------------
	protectedRoute.Handle("/user/register", a.hasAccess("user", "write")(http.HandlerFunc(a.handleUserRegistration))).Methods(http.MethodPost)
	protectedRoute.Handle("/users/all", a.hasAccess("user", "read")(http.HandlerFunc(a.handleGetAllRegisteredUsers))).Methods(http.MethodGet)
	clientRoute.HandleFunc("/user/login", a.handleUserLogin).Methods(http.MethodPost)
	protectedRoute.HandleFunc("/logout", a.handleUserLogout).Methods(http.MethodGet)
	clientRoute.HandleFunc("/user/{id}", a.handleGetUserByID).Methods(http.MethodGet)
	protectedRoute.Handle("/user/delete/{id}", a.hasAccess("user", "delete")(http.HandlerFunc(a.handleDeleteUser))).Methods(http.MethodDelete)
	clientRoute.HandleFunc("/user/stats/{id}", a.handleGetUserStats).Methods(http.MethodGet)
	clientRoute.HandleFunc("/user/update/{id}", a.handleUpdateUserInfo).Methods(http.MethodPut)
	protectedRoute.HandleFunc("/fetch/user/info", a.handleGetInfoBasedOnToken).Methods(http.MethodGet)

	// -----------------------IP-LOOKUP----------------------------------------------------
	protectedRoute.Handle("/ip/lookup", a.hasAccess("ip-lookup", "write")(http.HandlerFunc(a.handleIPLookup))).Methods(http.MethodPost)
	protectedRoute.Handle("/ip/lookup/history", a.hasAccess("ip-lookup", "read")(http.HandlerFunc(a.handleGetAllIPLookup))).Methods(http.MethodGet)
	protectedRoute.Handle("/ip/lookup/{id}", a.hasAccess("ip-lookup", "read")(http.HandlerFunc(a.handleGetAIPLookup))).Methods(http.MethodGet)
	protectedRoute.Handle("/ip/lookup/delete/{id}", a.hasAccess("ip-lookup", "delete")(http.HandlerFunc(a.handleDeleteIPLookupData))).Methods(http.MethodDelete)

	// ------------------ROLES--------------------------
	clientRoute.HandleFunc("/roles/add", a.handleAddRoles).Methods(http.MethodPost)
	clientRoute.HandleFunc("/roles", a.handleGetAllRoles).Methods(http.MethodGet)
	clientRoute.HandleFunc("/role/{id}", a.handleGetRoleByID).Methods(http.MethodGet)
	clientRoute.HandleFunc("/role/delete/{id}", a.handleDeleteRole).Methods(http.MethodDelete)

	// --------------------------PORT-ANALYSIS---------------------
	protectedRoute.Handle("/scan/port", a.hasAccess("port-scan", "write")(http.HandlerFunc(a.HandlePortScan))).Methods(http.MethodPost)
	protectedRoute.Handle("/scan/service", a.hasAccess("port-scan", "write")(http.HandlerFunc(a.HandleServiceDetection))).Methods(http.MethodPost)
	protectedRoute.Handle("/services", a.hasAccess("port-scan", "read")(http.HandlerFunc(a.handleGetAllDetectedServices))).Methods(http.MethodGet)
	protectedRoute.Handle("/services/stats", a.hasAccess("port-scan", "read")(http.HandlerFunc(a.handleFetchStatsForAllHistory))).Methods(http.MethodGet)
	protectedRoute.Handle("/scan/history/{id}", a.hasAccess("port-scan", "read")(http.HandlerFunc(a.handleGetServiceByID))).Methods(http.MethodGet)
	protectedRoute.Handle("/service/delete/{id}", a.hasAccess("port-scan", "delete")(http.HandlerFunc(a.handleServiceDelete))).Methods(http.MethodDelete)
	protectedRoute.Handle("/service/stats/{id}", a.hasAccess("port-scan", "read")(http.HandlerFunc(a.handleFetchStatsByServiceID))).Methods(http.MethodGet)
	protectedRoute.Handle("/service/user/stats/{userID}", a.hasAccess("port-scan", "read")(http.HandlerFunc(a.handleFetchStatsForUser))).Methods(http.MethodGet)
	clientRoute.HandleFunc("/service/scan/vulnerability", func(w http.ResponseWriter, r *http.Request) {
		a.ServeWS(w, r)
	})

	// ---------------------PCAP-FILE-ANALYSIS------------------------
	protectedRoute.Handle("/pcap/scan/{id}", a.hasAccess("pcap-scan", "read")(http.HandlerFunc(a.handleAnalyzeOfPCAP))).Methods(http.MethodGet)
	protectedRoute.Handle("/pcap/upload", a.hasAccess("pcap-scan", "write")(http.HandlerFunc(a.handleUploadPCAPFile))).Methods(http.MethodPost)
	protectedRoute.Handle("/pcap/metas", a.hasAccess("pcap-scan", "read")(http.HandlerFunc(a.handleGetAllPcapMetaData))).Methods(http.MethodGet)
	protectedRoute.Handle("/pcap/delete/{id}", a.hasAccess("pcap-scan", "delete")(http.HandlerFunc(a.handleDeletePCAPMetaData))).Methods(http.MethodDelete)

	// -----------------------AD-ROUTES-----------------------------------
	clientRoute.HandleFunc("/ad/checkhealth", a.handleADHealthCheck).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/authenticate", a.handleADAuthentication).Methods(http.MethodPost)
	// ------------------AD-USER----------------------------------------------
	clientRoute.HandleFunc("/ad/object/user/add", a.handleCreateNewUser).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/users", a.handleGetAllUsers).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/user", a.handleUserByDN).Methods(http.MethodPost)

	// ----------------AD-GROUPS--------------------------------------------
	clientRoute.HandleFunc("/ad/object/group/add", a.handleCreateNewGroup).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/groups", a.handleGetAllGroups).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/group", a.handleGetUserByDN).Methods(http.MethodPost)

	// --------------------AD-OU---------------------------------------------
	clientRoute.HandleFunc("/ad/object/ou/add", a.handleCreateNewOU).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/ous", a.handleGetAllOU).Methods(http.MethodPost)
	clientRoute.HandleFunc("/ad/object/ou", a.handleGetOUByDN).Methods(http.MethodPost)

	// --------------------------REPORT-GENERATOR-------------------------------
	clientRoute.HandleFunc("/generate/report", a.handleGenerateReport).Methods(http.MethodPost)

	corsOptions := cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "DELETE"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Content-Length", "Application-Encoding", "Authorization"},
	}
	c := cors.New(corsOptions)

	handler := c.Handler(router)
	a.httpServer = &http.Server{Addr: addr, Handler: handler}
	return a.httpServer.ListenAndServe()
}

func (a *APIServer) ConnectToDB() error {
	mongoURL := os.Getenv("MONGO_URL")
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
	a.clientStore = db.NewClientStore(client, "god_adshield", a.logger)

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
