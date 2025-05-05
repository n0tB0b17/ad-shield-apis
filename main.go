package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bob17/adpis/internal/api"
	"github.com/bob17/adpis/internal/logger"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("error while reading env file")
	}

	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		fmt.Println("Log path is empty make sure to assign a path to log file")
		return
	}

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
