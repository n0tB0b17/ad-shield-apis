package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bob17/adpis/internal/api"
	"github.com/bob17/adpis/internal/logger"
)

func main() {
	logPath := "/home/baiman/Desktop/active-directory-scanner/logs-file/log.txt"
	fileLogger, err := logger.NewFileLogger(logger.Debug, logPath)
	if err != nil {
		fmt.Println("Error while initializing logger")
		return
	}

	api := api.NewAPIServer(fileLogger)
	fmt.Printf("Starting API server at: %d \n", api.Port)
	if err := api.Start(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Unable to start API server: %v", err)
	}
}
