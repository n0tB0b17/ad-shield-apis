package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

	fileSizeInMB := float64(handler.Size*8) / 1_000_000
	resp := map[string]interface{}{
		"message":     "pcap upload",
		"description": "pcap file has been uploaded",
		"status":      "success",
		"size":        fileSizeInMB,
		"name":        handler.Filename,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
