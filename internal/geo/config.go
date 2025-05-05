package geo

type GeoConfig struct {
	Target  string
	Verbose bool
	Retries int
	Timeout int
}

func NewGeoConfig(target string) *GeoConfig {
	return &GeoConfig{
		Target:  target,
		Verbose: false,
		Retries: 3,
		Timeout: 10,
	}
}
