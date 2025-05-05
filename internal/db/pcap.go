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

type PCAPAnalysisResult struct {
	// General statistics
	TotalPCAPs        int64          `json:"total_pcaps"`
	TotalStorageBytes int64          `json:"total_storage_bytes"`
	AverageFileSize   int64          `json:"average_file_size"`
	LargestFile       *PCAPMetaData  `json:"largest_file"`
	SmallestFile      *PCAPMetaData  `json:"smallest_file"`
	OldestPCAP        *PCAPMetaData  `json:"oldest_pcap"`
	NewestPCAP        *PCAPMetaData  `json:"newest_pcap"`
	RecentlyAnalyzed  []PCAPMetaData `json:"recently_analyzed"`

	// File type statistics
	ContentTypeBreakdown []ContentTypeCount `json:"content_type_breakdown"`

	// Temporal statistics
	UploadsByHour       []HourlyUploadCount  `json:"uploads_by_hour"`
	UploadsByDay        []DailyUploadCount   `json:"uploads_by_day"`
	UploadsByMonth      []MonthlyUploadCount `json:"uploads_by_month"`
	UploadActivityTrend []UploadTrendPoint   `json:"upload_activity_trend"`

	// Analysis statistics
	AnalyzedCount      int64         `json:"analyzed_count"`
	UnanalyzedCount    int64         `json:"unanalyzed_count"`
	AvgAnalysisLatency time.Duration `json:"avg_analysis_latency"`
}

// Supporting structs for analysis results
type ContentTypeCount struct {
	ContentType string `json:"content_type"`
	Count       int    `json:"count"`
}

type HourlyUploadCount struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type DailyUploadCount struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type MonthlyUploadCount struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

type UploadTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
}

type PCAPMetaData struct {
	ID               bson.ObjectID `bson:"_id,omit" json:"id"`
	OriginalFileName string        `bson:"original_file_name" json:"original_file_name"`
	StoredFileName   string        `bson:"stored_file_name" json:"stored_file_name"`
	StoragePath      string        `bson:"storage_path" json:"storage_path"`
	FileSizeBytes    int64         `bson:"file_size_bytes" json:"file_size_bytes"`
	FileHash         string        `bson:"file_hash" json:"file_hash"`
	ContentType      string        `bson:"content_type" json:"content_type"`
	UploadedBy       bson.ObjectID `bson:"uploaded_by" json:"uploaded_by"`
	UploadedAt       time.Time     `bson:"uploaded_at" json:"uploaded_at"`
	LastAnalyzedTime *time.Time    `bson:"last_analyzed_time, omit"`
}

type PCAPStore struct {
	c *mongo.Collection
}

func NewPCAPStore(client *mongo.Client, dbname string) *PCAPStore {
	dbClient := client.Database(dbname).Collection("pcap_metadata")

	idxModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "stored_file_name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := dbClient.Indexes().CreateOne(ctx, idxModel)
	if err != nil {
		fmt.Printf("error while creating new index: %v", err)
		return nil
	}

	return &PCAPStore{
		c: dbClient,
	}
}

func (ps *PCAPStore) AddNewPCAP(ctx context.Context, docs PCAPMetaData) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	resp, err := ps.c.InsertOne(ctx, docs)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("file already exist")
		}

		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to add to database, server acknowledged with false")
	}

	return nil
}

func (ps *PCAPStore) GetAllPCAP(ctx context.Context, limit, skip int64) ([]PCAPMetaData, error) {
	var docs []PCAPMetaData
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := ps.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}

	return docs, nil
}

func (ps *PCAPStore) GetPCAPByID(ctx context.Context, id bson.ObjectID) (*PCAPMetaData, error) {
	var meta PCAPMetaData
	if err := ps.c.FindOne(ctx, bson.M{"_id": id}).Decode(&meta); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &meta, nil
}

func (ps *PCAPStore) DeletePCAPByID(ctx context.Context, id bson.ObjectID) error {
	resp, err := ps.c.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}

	if resp.DeletedCount == 0 {
		return fmt.Errorf("delete count is zero, not deleted")
	}
	return nil
}

func (ps *PCAPStore) GenerateAnalysis(ctx context.Context) (*PCAPAnalysisResult, error) {
	// Get all PCAP metadata
	pcaps, err := ps.GetAllPCAP(ctx, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCAP metadata: %v", err)
	}

	if len(pcaps) == 0 {
		return &PCAPAnalysisResult{}, nil
	}

	result := &PCAPAnalysisResult{
		TotalPCAPs:           int64(len(pcaps)),
		ContentTypeBreakdown: make([]ContentTypeCount, 0),
		UploadsByHour:        make([]HourlyUploadCount, 24),
		UploadsByDay:         make([]DailyUploadCount, 0),
		UploadsByMonth:       make([]MonthlyUploadCount, 0),
		UploadActivityTrend:  make([]UploadTrendPoint, 0),
		RecentlyAnalyzed:     make([]PCAPMetaData, 0),
	}

	// Initialize hourly upload counts
	for i := 0; i < 24; i++ {
		result.UploadsByHour[i] = HourlyUploadCount{Hour: i, Count: 0}
	}

	// Initialize day of week counts
	daysOfWeek := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	for _, day := range daysOfWeek {
		result.UploadsByDay = append(result.UploadsByDay, DailyUploadCount{Day: day, Count: 0})
	}

	// Data structures for tracking statistics
	contentTypeCounts := make(map[string]int)
	var totalStorageBytes int64 = 0
	var largestFile, smallestFile *PCAPMetaData
	var oldestPCAP, newestPCAP *PCAPMetaData
	trendData := make(map[time.Time]int)
	var analyzedCount int64 = 0
	var totalAnalysisLatency time.Duration = 0

	for i, pcap := range pcaps {
		// Track file sizes
		totalStorageBytes += pcap.FileSizeBytes
		if largestFile == nil || pcap.FileSizeBytes > largestFile.FileSizeBytes {
			largestFile = &pcaps[i]
		}
		if smallestFile == nil || pcap.FileSizeBytes < smallestFile.FileSizeBytes {
			smallestFile = &pcaps[i]
		}

		// Track oldest/newest
		if oldestPCAP == nil || pcap.UploadedAt.Before(oldestPCAP.UploadedAt) {
			oldestPCAP = &pcaps[i]
		}
		if newestPCAP == nil || pcap.UploadedAt.After(newestPCAP.UploadedAt) {
			newestPCAP = &pcaps[i]
		}

		// Track content types
		contentType := pcap.ContentType
		if contentType == "" {
			contentType = "unknown"
		}
		contentTypeCounts[contentType]++

		// Track temporal patterns
		hour := pcap.UploadedAt.Hour()
		result.UploadsByHour[hour].Count++
		day := pcap.UploadedAt.Weekday().String()
		for i, d := range result.UploadsByDay {
			if d.Day == day {
				result.UploadsByDay[i].Count++
				break
			}
		}

		// Track monthly uploads
		monthYear := pcap.UploadedAt.Format("2006-01")
		found := false
		for i, m := range result.UploadsByMonth {
			if m.Month == monthYear {
				result.UploadsByMonth[i].Count++
				found = true
				break
			}
		}
		if !found {
			result.UploadsByMonth = append(result.UploadsByMonth, MonthlyUploadCount{
				Month: monthYear,
				Count: 1,
			})
		}

		// Track upload trend (daily)
		date := time.Date(pcap.UploadedAt.Year(), pcap.UploadedAt.Month(), pcap.UploadedAt.Day(), 0, 0, 0, 0, time.UTC)
		trendData[date]++

		// Track analysis statistics
		if pcap.LastAnalyzedTime != nil {
			analyzedCount++
			latency := pcap.LastAnalyzedTime.Sub(pcap.UploadedAt)
			totalAnalysisLatency += latency

			// Track recently analyzed (last 5)
			if len(result.RecentlyAnalyzed) < 5 {
				result.RecentlyAnalyzed = append(result.RecentlyAnalyzed, pcap)
			} else {
				// Replace the oldest if this one is newer
				for j, ra := range result.RecentlyAnalyzed {
					if pcap.LastAnalyzedTime.After(*ra.LastAnalyzedTime) {
						result.RecentlyAnalyzed[j] = pcap
						break
					}
				}
			}
		}
	}

	// Set general statistics
	result.TotalStorageBytes = totalStorageBytes
	result.AverageFileSize = totalStorageBytes / int64(len(pcaps))
	result.LargestFile = largestFile
	result.SmallestFile = smallestFile
	result.OldestPCAP = oldestPCAP
	result.NewestPCAP = newestPCAP

	// Process content types
	for contentType, count := range contentTypeCounts {
		result.ContentTypeBreakdown = append(result.ContentTypeBreakdown, ContentTypeCount{
			ContentType: contentType,
			Count:       count,
		})
	}
	sort.Slice(result.ContentTypeBreakdown, func(i, j int) bool {
		return result.ContentTypeBreakdown[i].Count > result.ContentTypeBreakdown[j].Count
	})

	// Process upload trend
	for date, count := range trendData {
		result.UploadActivityTrend = append(result.UploadActivityTrend, UploadTrendPoint{
			Timestamp: date,
			Count:     count,
		})
	}
	sort.Slice(result.UploadActivityTrend, func(i, j int) bool {
		return result.UploadActivityTrend[i].Timestamp.Before(result.UploadActivityTrend[j].Timestamp)
	})

	// Sort monthly uploads
	sort.Slice(result.UploadsByMonth, func(i, j int) bool {
		return result.UploadsByMonth[i].Month < result.UploadsByMonth[j].Month
	})

	// Sort recently analyzed
	sort.Slice(result.RecentlyAnalyzed, func(i, j int) bool {
		return result.RecentlyAnalyzed[i].LastAnalyzedTime.After(*result.RecentlyAnalyzed[j].LastAnalyzedTime)
	})

	// Set analysis statistics
	result.AnalyzedCount = analyzedCount
	result.UnanalyzedCount = int64(len(pcaps)) - analyzedCount
	if analyzedCount > 0 {
		result.AvgAnalysisLatency = totalAnalysisLatency / time.Duration(analyzedCount)
	}

	return result, nil
}
