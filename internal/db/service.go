package db

import (
	"context"
	"fmt"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type AnalysisResult struct {
	TotalScans           int           `json:"total_scans"`
	SuccessfulScans      int           `json:"successful_scans"`
	FailedScans          int           `json:"failed_scans"`
	AverageScanDuration  time.Duration `json:"average_scan_duration"`
	LongestScanDuration  time.Duration `json:"longest_scan_duration"`
	ShortestScanDuration time.Duration `json:"shortest_scan_duration"`
	TotalPortsScanned    int           `json:"total_ports_scanned"`
	AveragePortsPerScan  float64       `json:"average_ports_per_scan"`

	MostScannedAddresses []AddressScanCount `json:"most_scanned_addresses"`

	MostCommonOpenPorts []PortCount      `json:"most_common_open_ports"`
	MostCommonServices  []ServiceCount   `json:"most_common_services"`
	ServiceVersions     []ServiceVersion `json:"service_versions"`

	ScansByHour        []HourlyScanCount `json:"scans_by_hour"`
	ScansByDay         []DailyScanCount  `json:"scans_by_day"`
	RecentScanActivity []RecentScan      `json:"recent_scan_activity"`

	ScanStatusBreakdown    []StatusCount        `json:"scan_status_breakdown"`
	ServiceStatusBreakdown []ServiceStatusCount `json:"service_status_breakdown"`
}

type AddressScanCount struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

type PortCount struct {
	Port    int    `json:"port"`
	Count   int    `json:"count"`
	Service string `json:"service,omitempty"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}

type ServiceVersion struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type HourlyScanCount struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type DailyScanCount struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type RecentScan struct {
	Time          time.Time `json:"time"`
	TargetAddress string    `json:"target_address"`
	PortsScanned  int       `json:"ports_scanned"`
}

type StatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type ServiceStatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type ServiceResult struct {
	Addr    string `bson:"address" json:"address"`
	Port    int    `bson:"port" json:"port"`
	Status  string `bson:"status" json:"status"`
	Service string `bson:"service" json:"service"`
	Version string `bson:"version" json:"version"`
}

type PortScanHistory struct {
	ID                 bson.ObjectID   `bson:"_id,omit" json:"_id"`
	UserID             bson.ObjectID   `bson:"user_id,omit" json:"user_id"`
	TargetAddress      string          `bson:"target_address" json:"target_address"`
	RequestedPortRange string          `bson:"requested_port_range" json:"requested_port_range"`
	ScanStartTime      time.Time       `bson:"scan_start_time" json:"scan_start_time"`
	ScanEndTime        time.Time       `bson:"scan_end_time" json:"scan_end_time"`
	ScanDuration       time.Duration   `bson:"scan_duration" json:"scan_duration"`
	Status             string          `bson:"status" json:"status"`
	ScanDetail         []ServiceResult `bson:"scan_result_detail" json:"scan_result_detail"`
	CreatedAt          time.Time       `bson:"created_at" json:"created_at"`
}

type ServiceStore struct {
	c *mongo.Collection
}

func NewServiceStore(client *mongo.Client, dbname string) *ServiceStore {
	col := client.Database(dbname).Collection("port_scan")

	return &ServiceStore{
		c: col,
	}
}

func (s *ServiceStore) GetServiceByUserID(ctx context.Context, userID bson.ObjectID) ([]PortScanHistory, error) {
	var resp []PortScanHistory
	opts := options.Find()
	opts.SetLimit(100)
	opts.SetSkip(0)

	cursor, err := s.c.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *ServiceStore) GetAllServiceDetectedHistory(ctx context.Context, limit, skip int64) ([]PortScanHistory, error) {
	var resp []PortScanHistory
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := s.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *ServiceStore) AddDetectedService(ctx context.Context, docs PortScanHistory) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	resp, err := s.c.InsertOne(ctx, docs)
	if err != nil {
		fmt.Println("error while adding service to db")
		fmt.Println(err.Error())
		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to add service detection data for address: %s", docs.TargetAddress)
	}

	return nil
}

func (s *ServiceStore) GetDetectedServiceByID(ctx context.Context, id bson.ObjectID) (*PortScanHistory, error) {
	var serviceHistory PortScanHistory
	if err := s.c.FindOne(ctx, bson.M{"_id": id}).Decode(&serviceHistory); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}
	return &serviceHistory, nil
}

func (s *ServiceStore) DeleteServiceByID(ctx context.Context, id bson.ObjectID) error {
	resp, err := s.c.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		fmt.Printf("error while deleteting service by ID: %v \n", err)
		return nil
	}

	if resp.DeletedCount == 0 {
		return fmt.Errorf("delete count is zero, not deleted")
	}

	return nil
}

func (s *ServiceStore) AnalysisByUserID(ctx context.Context, id bson.ObjectID) (*AnalysisResult, error) {
	userHistory, err := s.GetServiceByUserID(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.generateAnalysis(ctx, userHistory)
}

func (s *ServiceStore) AnalyzeAll(ctx context.Context) (*AnalysisResult, error) {
	histories, err := s.GetAllServiceDetectedHistory(ctx, 100, 0)
	if err != nil {
		return nil, err
	}

	return s.generateAnalysis(ctx, histories)
}

func (s *ServiceStore) AnalyzeAService(ctx context.Context, id bson.ObjectID) (*AnalysisResult, error) {
	var services []PortScanHistory
	history, err := s.GetDetectedServiceByID(ctx, id)
	if err != nil {
		return nil, err
	}

	services = append(services, *history)

	return s.generateAnalysis(ctx, services)
}

func (s *ServiceStore) generateAnalysis(ctx context.Context, histories []PortScanHistory) (*AnalysisResult, error) {
	if len(histories) == 0 {
		return &AnalysisResult{}, nil
	}

	result := &AnalysisResult{
		TotalScans:           len(histories),
		MostScannedAddresses: make([]AddressScanCount, 0),
		MostCommonOpenPorts:  make([]PortCount, 0),
		MostCommonServices:   make([]ServiceCount, 0),
		ServiceVersions:      make([]ServiceVersion, 0),
		ScansByHour:          make([]HourlyScanCount, 24),
		ScansByDay:           make([]DailyScanCount, 0),
		RecentScanActivity:   make([]RecentScan, 0),
	}

	// Initialize hourly scan counts
	for i := 0; i < 24; i++ {
		result.ScansByHour[i] = HourlyScanCount{Hour: i, Count: 0}
	}

	// Initialize day of week counts
	daysOfWeek := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	for _, day := range daysOfWeek {
		result.ScansByDay = append(result.ScansByDay, DailyScanCount{Day: day, Count: 0})
	}

	// Data structures for tracking statistics
	addressCounts := make(map[string]int)
	openPortCounts := make(map[int]int)
	portServiceMap := make(map[int]string)
	serviceCounts := make(map[string]int)
	serviceVersionCounts := make(map[string]map[string]int)
	statusCounts := make(map[string]int)
	serviceStatusCounts := make(map[string]int)
	totalScanDuration := time.Duration(0)
	totalPortsScanned := 0

	// Process each scan history
	for _, history := range histories {
		// Track scan status
		statusCounts[history.Status]++
		if history.Status == "completed" {
			result.SuccessfulScans++
		} else {
			result.FailedScans++
		}

		// Track scan durations
		if result.LongestScanDuration < history.ScanDuration {
			result.LongestScanDuration = history.ScanDuration
		}
		if result.ShortestScanDuration == 0 || history.ScanDuration < result.ShortestScanDuration {
			result.ShortestScanDuration = history.ScanDuration
		}
		totalScanDuration += history.ScanDuration

		// Track target addresses
		addressCounts[history.TargetAddress]++

		// Track temporal patterns
		hour := history.ScanStartTime.Hour()
		result.ScansByHour[hour].Count++
		day := history.ScanStartTime.Weekday().String()
		for i, d := range result.ScansByDay {
			if d.Day == day {
				result.ScansByDay[i].Count++
				break
			}
		}

		// Track recent activity (last 10 scans)
		if len(result.RecentScanActivity) < 10 {
			result.RecentScanActivity = append(result.RecentScanActivity, RecentScan{
				Time:          history.ScanStartTime,
				TargetAddress: history.TargetAddress,
				PortsScanned:  len(history.ScanDetail),
			})
		}

		// Process scan details
		totalPortsScanned += len(history.ScanDetail)
		for _, detail := range history.ScanDetail {
			// Track service statuses
			serviceStatusCounts[detail.Status]++

			if detail.Status == "open" {
				// Track open ports
				openPortCounts[detail.Port]++
				portServiceMap[detail.Port] = detail.Service

				// Track services
				serviceCounts[detail.Service]++

				// Track service versions
				if detail.Version != "" {
					if _, exists := serviceVersionCounts[detail.Service]; !exists {
						serviceVersionCounts[detail.Service] = make(map[string]int)
					}
					serviceVersionCounts[detail.Service][detail.Version]++
				}
			}
		}
	}

	// Calculate averages
	result.AverageScanDuration = totalScanDuration / time.Duration(len(histories))
	result.TotalPortsScanned = totalPortsScanned
	result.AveragePortsPerScan = float64(totalPortsScanned) / float64(len(histories))

	// Process address counts
	for address, count := range addressCounts {
		result.MostScannedAddresses = append(result.MostScannedAddresses, AddressScanCount{
			Address: address,
			Count:   count,
		})
	}
	sort.Slice(result.MostScannedAddresses, func(i, j int) bool {
		return result.MostScannedAddresses[i].Count > result.MostScannedAddresses[j].Count
	})
	if len(result.MostScannedAddresses) > 10 {
		result.MostScannedAddresses = result.MostScannedAddresses[:10]
	}

	// Process open port counts
	for port, count := range openPortCounts {
		result.MostCommonOpenPorts = append(result.MostCommonOpenPorts, PortCount{
			Port:    port,
			Count:   count,
			Service: portServiceMap[port],
		})
	}
	sort.Slice(result.MostCommonOpenPorts, func(i, j int) bool {
		return result.MostCommonOpenPorts[i].Count > result.MostCommonOpenPorts[j].Count
	})
	if len(result.MostCommonOpenPorts) > 10 {
		result.MostCommonOpenPorts = result.MostCommonOpenPorts[:10]
	}

	// Process service counts
	for service, count := range serviceCounts {
		result.MostCommonServices = append(result.MostCommonServices, ServiceCount{
			Service: service,
			Count:   count,
		})
	}
	sort.Slice(result.MostCommonServices, func(i, j int) bool {
		return result.MostCommonServices[i].Count > result.MostCommonServices[j].Count
	})
	if len(result.MostCommonServices) > 10 {
		result.MostCommonServices = result.MostCommonServices[:10]
	}

	// Process service versions
	for service, versions := range serviceVersionCounts {
		for version, count := range versions {
			result.ServiceVersions = append(result.ServiceVersions, ServiceVersion{
				Service: service,
				Version: version,
				Count:   count,
			})
		}
	}
	sort.Slice(result.ServiceVersions, func(i, j int) bool {
		return result.ServiceVersions[i].Count > result.ServiceVersions[j].Count
	})
	if len(result.ServiceVersions) > 10 {
		result.ServiceVersions = result.ServiceVersions[:10]
	}

	// Process status breakdown
	for status, count := range statusCounts {
		result.ScanStatusBreakdown = append(result.ScanStatusBreakdown, StatusCount{
			Status: status,
			Count:  count,
		})
	}

	// Process service status breakdown
	for status, count := range serviceStatusCounts {
		result.ServiceStatusBreakdown = append(result.ServiceStatusBreakdown, ServiceStatusCount{
			Status: status,
			Count:  count,
		})
	}

	// Sort recent activity by time (newest first)
	sort.Slice(result.RecentScanActivity, func(i, j int) bool {
		return result.RecentScanActivity[i].Time.After(result.RecentScanActivity[j].Time)
	})

	return result, nil
}
