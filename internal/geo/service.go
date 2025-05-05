package geo

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bob17/adpis/internal/db"
)

type GeoService struct {
	config    *GeoConfig
	geoClient GeoClient
}

func NewGeoService(cfg *GeoConfig) *GeoService {
	return &GeoService{
		config:    cfg,
		geoClient: GetAPIClient(),
	}
}

func (gs *GeoService) Lookup() (*db.LookupResult, error) {
	result := &db.LookupResult{
		Target: gs.config.Target,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.config.Timeout)*time.Second)
	defer cancel()

	ip, err := gs.resolveTarget(ctx)
	if err != nil {
		return nil, err
	}
	result.IP = ip.String()

	info, err := gs.lookupGeoLocation(ctx, ip)
	if err != nil {
		if gs.config.Verbose {
			fmt.Printf("Warning: Geolocation lookup failed: %v\n", err)
		}
	} else {
		result.GeoInfo = info
	}

	hostnames, err := gs.lookupReverseDNS(ctx, ip)
	if err != nil {
		if gs.config.Verbose {
			fmt.Printf("Warning: ReverseDNS lookup failed: %v \n", err)
		}
	} else {
		result.Hostnames = hostnames
	}

	return result, nil
}

func (gs *GeoService) resolveTarget(ctx context.Context) (net.IP, error) {
	if ip := net.ParseIP(gs.config.Target); ip != nil {
		return ip, nil
	}

	for attempt := 0; attempt < gs.config.Retries; attempt++ {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", gs.config.Target)

		if err == nil && len(ips) > 0 {
			return ips[0], nil
		}

		if attempt == gs.config.Retries {
			return nil, fmt.Errorf("failed to resolve domain after %d attempts: %w", gs.config.Retries, err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt*attempt+1) * time.Second):
		}
	}

	return nil, fmt.Errorf("failed to resolve domain")
}

func (gs *GeoService) lookupGeoLocation(ctx context.Context, ip net.IP) (*db.GeoInfo, error) {
	for attempt := 0; attempt < gs.config.Retries; attempt++ {
		info, err := gs.geoClient.LookUp(ctx, ip)
		if err == nil {
			return info, nil
		}

		if attempt == gs.config.Retries {
			return nil, fmt.Errorf("failed to lookup geolocation after %d attempts: %w", gs.config.Retries, err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt*attempt+1) * time.Second):
		}
	}
	return nil, fmt.Errorf("failed to identify target's geo location")
}

func (gs *GeoService) lookupReverseDNS(ctx context.Context, ip net.IP) ([]string, error) {
	for attempt := 0; attempt < gs.config.Retries; attempt++ {
		hostname, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
		if err == nil {
			return hostname, nil
		}

		if attempt == gs.config.Retries {

		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt*attempt+1) * time.Second):
		}
	}
	return nil, fmt.Errorf("failed to lookup reverse DNS")
}
