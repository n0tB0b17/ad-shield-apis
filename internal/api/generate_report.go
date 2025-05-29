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
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/genreport"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/pkg/utils"
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
	} else if reqBody.ContentType == "PCAP_REPORT" {
		content = content.(*db.PCAPMetaData)
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
