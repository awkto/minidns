// Package provider fetches authoritative zone data from cloud DNS providers
// so unbound can serve a local mirror.
package provider

import (
	"fmt"

	"github.com/awkto/minidns/internal/config"
)

// Provider fetches a complete zone as a master-format zone file.
type Provider interface {
	Name() string
	FetchZone(zone string) (string, error)
}

// For returns the provider implementation for a config zone entry.
// Roadmap: route53, azure, cloudflare.
func For(c *config.Config, name string) (Provider, error) {
	switch name {
	case "digitalocean", "do", "":
		token, err := c.DOToken()
		if err != nil {
			return nil, err
		}
		return &DigitalOcean{Token: token}, nil
	default:
		return nil, fmt.Errorf("unsupported provider %q (supported: digitalocean; roadmap: route53, azure, cloudflare)", name)
	}
}
