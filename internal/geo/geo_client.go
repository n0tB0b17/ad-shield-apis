package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
)

type GeoClient interface {
	LookUp(ctx context.Context, ip net.IP) (*db.GeoInfo, error)
}

type IPAPIClient struct {
	httpClient *http.Client
}

func GetAPIClient() *IPAPIClient {
	return &IPAPIClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (i *IPAPIClient) LookUp(ctx context.Context, ip net.IP) (*db.GeoInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip.String())
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fmt.Printf("geo::LookUp:: error while creating new request: %v \n", err)
		return nil, err
	}

	resp, err := i.httpClient.Do(req)
	if err != nil {
		fmt.Printf("geo::LookUp:: error while getting response: %v \n", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("geo::LookUp:: got bad status code \n")
		return nil, fmt.Errorf("got bad status code")
	}

	var apiResp struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		fmt.Printf("geo::lookup:: error while decoding response body: %v \n", err)
		return nil, err
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("status not success")
	}

	return &db.GeoInfo{
		Country:      apiResp.Country,
		CountryCode:  apiResp.CountryCode,
		Region:       apiResp.RegionName,
		City:         apiResp.City,
		Zip:          apiResp.Zip,
		Latitude:     apiResp.Lat,
		Longitude:    apiResp.Lon,
		Timezone:     apiResp.Timezone,
		ISP:          apiResp.ISP,
		Organization: apiResp.Org,
		ASN:          apiResp.AS,
	}, nil
}
