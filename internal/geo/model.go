package geo

import (
	"net"
)

type GeoInfo struct {
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Zip          string  `json:"zip"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Timezone     string  `json:"timezone"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
	ASN          string  `json:"asn"`
}

type LookupResult struct {
	Target    string   `json:"target"`
	IP        net.IP   `json:"ip"`
	GeoInfo   *GeoInfo `json:"geo_info"`
	Hostnames []string `json:"hostnames"`
}
