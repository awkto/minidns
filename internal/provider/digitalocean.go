package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DigitalOcean pulls zones via the DO API, which conveniently returns the
// complete rendered zone file (GET /v2/domains/<name> → domain.zone_file).
type DigitalOcean struct {
	Token string
}

func (d *DigitalOcean) Name() string { return "digitalocean" }

var doClient = &http.Client{Timeout: 30 * time.Second}

func (d *DigitalOcean) FetchZone(zone string) (string, error) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	req, err := http.NewRequest("GET", "https://api.digitalocean.com/v2/domains/"+zone, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	resp, err := doClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("digitalocean api: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("zone %s not found on this DigitalOcean account", zone)
	case http.StatusUnauthorized:
		return "", fmt.Errorf("digitalocean api: token rejected (401)")
	default:
		return "", fmt.Errorf("digitalocean api: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Domain struct {
			Name     string `json:"name"`
			ZoneFile string `json:"zone_file"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("digitalocean api: parse response: %w", err)
	}
	if strings.TrimSpace(out.Domain.ZoneFile) == "" {
		return "", fmt.Errorf("digitalocean api: empty zone_file for %s", zone)
	}
	return out.Domain.ZoneFile, nil
}
