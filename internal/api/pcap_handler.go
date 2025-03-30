package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/bob17/adpis/internal/analysis/application"
	"github.com/bob17/adpis/internal/analysis/network"
	"github.com/bob17/adpis/internal/analysis/transport"
	"github.com/bob17/adpis/internal/pcap"
	"github.com/google/gopacket"
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
