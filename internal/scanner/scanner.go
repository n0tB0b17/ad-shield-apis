package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"github.com/bob17/adpis/pkg/utils"
)

type ScanResult struct {
	Addr   string
	Port   int
	Status string
}

type Scanner interface {
	Scan(addr string, portRange string) []ScanResult
}

type PortScanner struct {
	Logger     logger.Logger
	Timeout    time.Duration
	MaxWorkers int
	IsRoot     bool
}

func NewPortScanner(l logger.Logger, t time.Duration, mw int) *PortScanner {
	groot := utils.IsRoot()
	return &PortScanner{
		Logger:     l,
		Timeout:    t,
		MaxWorkers: mw,
		IsRoot:     groot,
	}
}

func (ps *PortScanner) Scan(addr string, portRange string) []ScanResult {
	ports := utils.ParsePortRange(portRange)
	resp := make([]ScanResult, 0, len(ports))

	var wg sync.WaitGroup
	jobs := make(chan int, len(ports))
	result := make(chan ScanResult, len(ports))

	for i := 0; i <= ps.MaxWorkers; i++ {
		wg.Add(1)
		go ps.worker(addr, jobs, result, &wg)
	}

	for _, port := range ports {
		jobs <- port
	}
	close(jobs)
	wg.Wait()
	close(result)

	for scanResp := range result {
		resp = append(resp, scanResp)
	}

	return resp
}

// if any jobs is being pushed, run scanPort function immediately and add result into resp channel
func (ps *PortScanner) worker(addr string, jobs <-chan int, resp chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for port := range jobs {
		result := ps.scanPort(addr, port)
		resp <- result
	}
}

func (ps *PortScanner) scanPort(addr string, port int) ScanResult {
	if ps.IsRoot {
		ps.Logger.Info("SYNC scan......")
		isOpen, err := synScan(addr, port)
		if err != nil {
			ps.Logger.Warn(fmt.Sprintf("SYN scan failed: %s:%d >> Error: %v ", addr, port, err))
			return ScanResult{Port: port, Status: "closed", Addr: addr}
		}

		if isOpen {
			ps.Logger.Info(fmt.Sprintf("Port: %d is Open (SYN) scan", port))
			return ScanResult{Port: port, Status: "open", Addr: addr}
		}

		ps.Logger.Debug(fmt.Sprintf("Port: %d is Closed (SYN) scan", port))
		return ScanResult{Port: port, Status: "closed"}
	}

	ps.Logger.Debug("TCP-CONNECT scan running...")
	fullAddr := fmt.Sprintf("%s:%d", addr, port)
	conn, err := net.DialTimeout("tcp", fullAddr, ps.Timeout)
	if err != nil {
		ps.Logger.Debug(fmt.Sprintf("Port %d is closed >> %v", port, err))
		return ScanResult{Port: port, Status: "closed", Addr: addr}
	}
	defer conn.Close()
	ps.Logger.Info(fmt.Sprintf("Port %d is open", port))
	return ScanResult{Port: port, Status: "open", Addr: addr}
}
