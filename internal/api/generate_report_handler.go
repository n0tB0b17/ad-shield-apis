package api

import (
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/analysis/application"
	"github.com/bob17/adpis/internal/analysis/network"
	"github.com/bob17/adpis/internal/analysis/transport"
	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/genreport"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/internal/pcap"
	"github.com/bob17/adpis/internal/vulners"
	"github.com/bob17/adpis/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "Invalid method",
			"description": "Try method post to generate report",
			"status":      "failed",
		})
		return
	}

	var reqBody models.RequestReportGenerate
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "Invalid body",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	reportFilename := strings.TrimSpace(reqBody.FileName)
	if reportFilename == "" {
		reportFilename = "report.pdf"
	}

	if !strings.HasSuffix(strings.ToLower(reportFilename), ".pdf") {
		reportFilename += ".pdf"
	}

	filepath.Base(reportFilename)

	user, err := a.userStore.GetUserByID(r.Context(), reqBody.UserId)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "user not found",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	content := a.validateContentType(reqBody.ContentType, reqBody.ContentId)
	if content == nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "content not found",
			"description": fmt.Sprintf("given content-type in request body is invalid: %s", reqBody.ContentType),
			"status":      "failed",
		})
		return
	}

	client := r.Context().Value(utils.CLIENT_KEY).(*db.ADClient)
	pr, pg, pb, _ := utils.HexToRGB(client.PrimaryColorHex)
	sr, sg, sb, _ := utils.HexToRGB(client.SecondaryColorHex)
	regen := genreport.NewReportGenerator(reqBody.ContentType)
	theme := &genreport.ColorTheme{
		Primary:   color.RGBA{R: uint8(pr), B: uint8(pb), G: uint8(pg)},
		Secondary: color.RGBA{R: uint8(sr), B: uint8(sb), G: uint8(sg)},
	}

	brandingInfo := genreport.BrandingInfo{
		CompanyName:       client.ClientName,
		Addr:              client.Headquarter,
		AdminEmailAddress: client.AdminEmail,
		Theme:             theme,
	}

	_ = regen.SetBranding(brandingInfo)
	_ = regen.SetUser(user)

	if reqBody.ContentType == "PORT_REPORT" {
		content = content.(*db.PortScanHistory)
		portScanHistory := content.(*db.PortScanHistory)

		portAnalysis := make(map[string]interface{})
		resp, _ := a.getVulnersPortScanResult(portScanHistory.ScanDetail)

		portAnalysis["vulnersAnalysis"] = resp
		regen.SetAnalysis(portAnalysis)
	} else if reqBody.ContentType == "PCAP_REPORT" {
		content = content.(*db.PCAPMetaData)

		pcapMetaData := content.(*db.PCAPMetaData)
		analysis := a.getPCAPAnalysisResult(pcapMetaData.StoragePath)
		regen.SetAnalysis(analysis)
	}

	if err := regen.SetContent(content); err != nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "unable to set content",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	gen_byte, err := regen.Generate()
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	randomId := uuid.New().String()
	fileName := fmt.Sprintf("%s_%s", randomId, reportFilename)
	fullPath := filepath.Join(a.pdfDirectory, fileName)

	if err := os.WriteFile(fullPath, gen_byte, 0644); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "Failed to save PDF",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "PDF generated successfully",
		"status":       "success",
		"download_url": fmt.Sprintf("/%s/report/download/%s", client.ID.Hex(), fileName),
		"filename":     reportFilename,
		"size":         len(gen_byte),
	})
}

func (a *APIServer) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to download generated file, method should be get",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	fileName := vars["fileName"]
	fullPath := filepath.Join(a.pdfDirectory, fileName)

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "file not found",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	http.ServeFile(w, r, fullPath)
}

func (a *APIServer) validateContentType(t string, contentId bson.ObjectID) interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var content interface{}
	switch t {
	case "PCAP_REPORT":
		content, _ = a.pcapStore.GetPCAPByID(ctx, contentId)
	case "PORT_REPORT":
		content, _ = a.serviceDetectionStore.GetDetectedServiceByID(ctx, contentId)
	}

	return content
}

func (a *APIServer) getPCAPAnalysisResult(storagePath string) map[string]interface{} {
	numOfWorker := 10
	pcapReader := pcap.NewPCAPReader(storagePath)
	networkAnalysis := network.NewNetworkAnalyzer()
	transportAnalysis := transport.NewTransportAnalyzer()
	applicationAnalysis := application.NewApplicationLayerAnalyzer()
	packetChan := make(chan gopacket.Packet, 100)

	var wg sync.WaitGroup
	wg.Add(1)
	go pcapReader.ReadPackets(packetChan, &wg)
	for i := 0; i < numOfWorker; i++ {
		wg.Add(3)
		go networkAnalysis.ProcessPackets(packetChan, &wg)
		go transportAnalysis.ProcessPackets(packetChan, &wg)
		go applicationAnalysis.ProcessPackets(packetChan, &wg)
	}
	wg.Wait()

	networkResult := networkAnalysis.GetResult()
	networkStats := network.NetworkStats{
		PacketCount:       networkResult["TotalPacket"].(int),
		FragmentedPackets: networkResult["FragmentedPackets"].(int),
		IpStats:           networkResult["IPStats"].(map[string]int),
		ReassembledFlows:  networkResult["ReassembledFlows"].(int),
		TTLStats:          networkResult["TTLStats"].(map[uint8]int),
		ProtocolDist:      networkResult["ProtocolDist"].(map[string]int),
	}

	transportResult := transportAnalysis.GetResult()
	transportStats := transport.TransportStats{
		TCPPacketCount:  transportResult["TCPPacketCount"].(int),
		UDPPacketCount:  transportResult["UDPPacketCount"].(int),
		PortStats:       transportResult["PortStats"].(map[int]int),
		TCPConnection:   transportResult["TCPConnections"].(int),
		Retransmission:  transportResult["Retransmissions"].(int),
		InvalidTCPFlags: transportResult["InvalidTCPFlags"].(int),
		UDPFloodPorts:   transportResult["UDPFloodPorts"].(map[int]int),
		StreamData:      transportResult["StreamData"].(map[string]int),
	}

	applicationResult := applicationAnalysis.GetResult()
	applicationStats := application.ApplicationStats{
		ProtocolStats: make(map[string]*application.ApplicationProtocolStats),
		TLSStats:      application.TLSMeta{},
	}

	if protoStats, ok := applicationResult["ProtocolStats"].(map[string]interface{}); ok {
		for proto, stats := range protoStats {
			protoData := stats.(map[string]interface{})
			appProtoStats := &application.ApplicationProtocolStats{
				PacketCount:   protoData["PacketCount"].(int),
				RequestCount:  protoData["RequestCount"].(int),
				ResponseCount: protoData["ResponseCount"].(int),
				Domains:       protoData["Domains"].(map[string]int),
				PayloadSize:   protoData["PayloadSizes"].(map[string]int),
				Anomalies:     protoData["Anomalies"].(map[string]int),
			}
			applicationStats.ProtocolStats[proto] = appProtoStats
		}
	}

	if tlsStats, ok := applicationResult["TLSStats"].(map[string]interface{}); ok {
		tlsMeta := application.TLSMeta{
			CipherSuites: tlsStats["CipherSuites"].(map[string]int),
			Versions:     tlsStats["Versions"].(map[string]int),
			Certificates: tlsStats["Certificates"].(int),
			SNI:          tlsStats["SNI"].(map[string]int),
		}
		applicationStats.TLSStats = tlsMeta
	}

	return map[string]interface{}{
		"networkAnalysis":     networkStats,
		"transportAnalysis":   transportStats,
		"applicationAnalysis": applicationStats,
	}
}

func (a *APIServer) getVulnersPortScanResult(scanned_port []db.ServiceResult) ([]*vulners.Resp, error) {
	vul_scanner := vulners.GetVulners(3)

	resp_holder := make([]*vulners.Resp, len(scanned_port))
	for i := 0; i < len(scanned_port); i++ {
		resp := scanned_port[i]
		vuln_resp, err := vul_scanner.Query(resp.Service, resp.Version)
		if err == nil {
			resp_holder = append(resp_holder, vuln_resp)
		}
	}

	return resp_holder, nil
}
