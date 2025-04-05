package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/google/gopacket"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handlePCAPFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}

	const maxUploadSize = 100 * 1024 * 1024
	if err := r.ParseMultipartForm(int64(maxUploadSize)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("pcap_file")
	if err != nil {
		http.Error(w, fmt.Sprintf("error retreving the file: %v \n", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	a.logger.Debug(fmt.Sprintf("Uploaded file name: %s \n", handler.Filename))
	a.logger.Debug(fmt.Sprintf("Uploaded file size: %d \n", handler.Size))

	osFile, err := os.CreateTemp("", "pcap_*")
	if err != nil {
		http.Error(w, fmt.Sprintf("error while creating temporary file: %v \n", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(osFile.Name())
	defer osFile.Close()

	_, err = io.Copy(osFile, file)
	if err != nil {
		http.Error(w, fmt.Sprintf("error while copying the file: %v \n", err), http.StatusInternalServerError)
		return
	}

	osFile.Sync()

	pcapReader := pcap.NewPCAPReader(osFile.Name())
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
	resp := map[string]interface{}{
		"message":                   "pcap upload",
		"description":               "pcap file has been uploaded",
		"status":                    "success",
		"name":                      handler.Filename,
		"network_layer_metrics":     networkAnalyzer.GetResult(),
		"transport_layer_metrics":   transportAnalyzer.GetResult(),
		"application_layer_metrics": appAnalyzer.GetResult(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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

	docs := db.PCAPMetaData{
		ID:               bson.NewObjectID(),
		OriginalFileName: handler.Filename,
		StoredFileName:   storedFileName,
		StoragePath:      pcapStoragePath,
		FileSizeBytes:    handler.Size,
		FileHash:         fileHash,
		ContentType:      r.Header.Get("Content-Type"),
		UploadedAt:       time.Now(),
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

	responseWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":        "added pcap-metadata",
		"description":    "pcap file uploaded, now you can start analysis process",
		"status":         "success",
		"pcap_meta_data": docs,
	})
}
