package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/analysis/application"
	"github.com/bob17/adpis/internal/analysis/network"
	"github.com/bob17/adpis/internal/analysis/transport"
	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/pcap"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/bob17/adpis/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleAnalyzeOfPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to analyze with ID, try method GET",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	isValidID := isValidObjectID(id)
	if !isValidID {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid id",
			"description": "id provided in path parameter is invalid",
			"status":      "failed",
		})
		return
	}

	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
			"message":     "invalid objectID",
			"description": "unable to convert path id to objectID",
			"status":      "failed",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	meta, err := a.pcapStore.GetPCAPByID(ctx, objectID)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": "check server logs for more information",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	if meta == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "pcap not found",
			"description": "given id don't have any associated pcap file in storage",
			"status":      "failed",
		})
		return
	}

	pcapReader := pcap.NewPCAPReader(meta.StoragePath)
	networkAnalyzer := network.NewNetworkAnalyzer()
	transportAnalyzer := transport.NewTransportAnalyzer()
	appAnalyzer := application.NewApplicationLayerAnalyzer()

	packetChan := make(chan gopacket.Packet, 100)
	var wg sync.WaitGroup

	wg.Add(1)
	go pcapReader.ReadPackets(packetChan, &wg)
	numOfWorker := 10
	for i := 1; i < numOfWorker; i++ {
		wg.Add(3)
		go networkAnalyzer.ProcessPackets(packetChan, &wg)
		go transportAnalyzer.ProcessPackets(packetChan, &wg)
		go appAnalyzer.ProcessPackets(packetChan, &wg)
	}

	wg.Wait()

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "auth failed",
			"description": "auth_claim key not fetched",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "analyze_pcap_file",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":                   "pcap upload",
		"description":               "pcap file has been uploaded",
		"status":                    "success",
		"meta":                      meta,
		"network_layer_metrics":     networkAnalyzer.GetResult(),
		"transport_layer_metrics":   transportAnalyzer.GetResult(),
		"application_layer_metrics": appAnalyzer.GetResult(),
	})
}

func (a *APIServer) handleUploadPCAPFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "failed",
			"description": "invalid method to upload pcap file",
			"status":      "failed",
		})

		return
	}

	maxUploadSize := 100 * 1024 * 1024
	if err := r.ParseMultipartForm(int64(maxUploadSize)); err != nil {
		responseWithJSON(w, http.StatusInsufficientStorage, map[string]interface{}{
			"message":     "file size BIG",
			"description": "file size exceeded our limit, make sure file size is > 100 MB",
			"status":      "failed",
			"error":       err.Error(),
		})

		return
	}

	file, handler, err := r.FormFile("pcap_file")
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "invalid key",
			"description": "invalid key provided to upload file",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	defer file.Close()
	a.logger.Debug(fmt.Sprintf("Uploaded file name: %s \n", handler.Filename))

	if handler.Size == 0 {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "invalid upload",
			"description": "file uploaded don't seems to have any content",
			"status":      "failed",
		})

		return
	}

	if err := os.MkdirAll(a.pcapDirectory, 0750); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "directory not found",
			"description": "pcap file directory not found, unable to create it",
			"status":      "failed",
			"error":       err.Error(),
		})

		return
	}

	storedFileName := uuid.New().String() + filepath.Ext(handler.Filename)
	pcapStoragePath := filepath.Join(a.pcapDirectory, storedFileName)

	destPath, err := os.Create(pcapStoragePath)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to create path",
			"description": "path not created to store pcap file",
			"status":      "failed",
			"error":       err.Error(),
		})
	}
	defer destPath.Close()

	hasher := sha256.New()
	teeReader := io.TeeReader(file, hasher)
	writtenBytes, err := io.Copy(destPath, teeReader)
	if err != nil {
		_ = destPath.Close()
		_ = os.Remove(pcapStoragePath)
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to copy",
			"description": "server was unable to copy file content from provided file",
			"status":      "failed",
			"error":       err.Error(),
		})

		return
	}

	if writtenBytes != handler.Size {
		_ = destPath.Close()
		_ = os.Remove(pcapStoragePath)
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "fully not copied",
			"description": "incomplete file content copy",
			"status":      "failed",
		})
		return
	}

	if err := destPath.Sync(); err != nil {
		// err
		a.logger.Debug(fmt.Sprintf("unable to flush destination path: %s", pcapStoragePath))
	}

	if err := destPath.Close(); err != nil {
		// err
		a.logger.Debug(fmt.Sprintf("unable to close destination path: %s", pcapStoragePath))
	}

	fileHash := hex.EncodeToString(hasher.Sum(nil))
	a.logger.Info(fmt.Sprintf("successfully copied uploaded pcap file: [%s] content to path: [%s]", handler.Filename, pcapStoragePath))

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "auth failed",
			"description": "auth_claim key not fetched",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	docs := db.PCAPMetaData{
		ID:               bson.NewObjectID(),
		OriginalFileName: handler.Filename,
		StoredFileName:   storedFileName,
		StoragePath:      pcapStoragePath,
		FileSizeBytes:    handler.Size,
		FileHash:         fileHash,
		ContentType:      r.Header.Get("Content-Type"),
		UploadedAt:       time.Now(),
		UploadedBy:       userID,
		LastAnalyzedTime: nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.pcapStore.AddNewPCAP(ctx, docs); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to add",
			"description": "internal server error while adding pcap meta-data to database",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "upload_pcap_file",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":        "added pcap-metadata",
		"description":    "pcap file uploaded, now you can start analysis process",
		"status":         "success",
		"pcap_meta_data": docs,
	})
}

func (a *APIServer) handleDeletePCAPMetaData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "make sure to use DELETE method",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	metaID := vars["id"]
	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)

	id, err := bson.ObjectIDFromHex(metaID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid service id",
			"description": "invalid service id provided, try with proper service detected id",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	if err := a.pcapStore.DeletePCAPByID(r.Context(), id); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}
	userID, _ := bson.ObjectIDFromHex(claim.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "delete_pcap_meta_data",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "deleted meta-data",
		"description": fmt.Sprintf("successfully deleted pcap meta-data for id: %s", metaID),
		"status":      "success",
	})
}

func (a *APIServer) handleGetAllPcapMetaData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "failed",
			"description": "invalid method to upload pcap file",
			"status":      "failed",
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	limit := int64(100)
	skip := int64(0)
	metas, err := a.pcapStore.GetAllPCAP(ctx, limit, skip)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": "unabel to get all pcap meta-data",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "auth failed",
			"description": "auth_claim key not fetched",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "get_all_pcap_meta_data",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("total number of pcap meta data: %d", len(metas)),
		"description": "successfully fetched all pcap meta data from database",
		"status":      "success",
		"pcaps":       metas,
	})
}
