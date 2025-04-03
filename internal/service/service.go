package service

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/logger"
	"github.com/bob17/adpis/internal/scanner"

	"github.com/bob17/adpis/pkg/utils"
)

type ServiceDetector interface {
	Detect(resp <-chan scanner.ScanResult) <-chan db.ServiceResult
}

type NMAPServiceDetector struct {
	Logger    logger.Logger
	Timeout   time.Duration
	MaxWorker int
}

func NewNMAPServiceDetector(l logger.Logger, t time.Duration, mw int) *NMAPServiceDetector {
	return &NMAPServiceDetector{
		Logger:    l,
		Timeout:   t,
		MaxWorker: mw,
	}
}

func (n *NMAPServiceDetector) Detect(resp <-chan scanner.ScanResult) <-chan db.ServiceResult {
	serviceResp := make(chan db.ServiceResult, n.MaxWorker)
	var wg sync.WaitGroup

	for i := 0; i < n.MaxWorker; i++ {
		wg.Add(1)
		go n.worker(resp, serviceResp, &wg)
	}

	go func() {
		wg.Wait()
		close(serviceResp)
	}()

	return serviceResp
}

func (n *NMAPServiceDetector) worker(scanResp <-chan scanner.ScanResult, serviceResp chan<- db.ServiceResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for resp := range scanResp {
		if resp.Status == "open" {
			result := n.detectService(resp.Port, resp.Addr)
			serviceResp <- result
		} else {
			serviceResp <- db.ServiceResult{
				Port:   resp.Port,
				Status: "closed",
				Addr:   resp.Addr,
			}
		}
	}
}

func (n *NMAPServiceDetector) detectService(port int, addr string) db.ServiceResult {
	cmd := exec.Command("nmap", "-sV", "-p", fmt.Sprintf("%d", port), "--host-timeout", n.Timeout.String(), addr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return db.ServiceResult{
			Addr:    addr,
			Port:    port,
			Status:  "open",
			Service: "unknown",
			Version: "unknown",
		}
	}

	outStr := string(output)
	service, version, err := utils.ParseNMAPOutput(outStr, port)
	if err != nil {
		fmt.Printf("Error running nmap on port for service detection: %s:%d \n", addr, port)
		n.Logger.Info(fmt.Sprintf("Error running nmap on port: %d", port))
		return db.ServiceResult{
			Addr:    addr,
			Port:    port,
			Status:  "open",
			Service: "unknown",
			Version: "unknown",
		}
	}

	return db.ServiceResult{
		Addr:    addr,
		Port:    port,
		Status:  "open",
		Service: service,
		Version: version,
	}
}
