package jwks

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

// fetchJWKSURI fetches the `jwks_uri` from the OpenID configuration
func fetchJWKSURI(issuer string) (string, error) {
	openIDConfigURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)
	resp, err := http.Get(openIDConfigURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response code: %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to decode OpenID configuration: %w", err)
	}

	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OpenID configuration")
	}

	return config.JWKSURI, nil
}

// fetchJWKS fetches the JWKS from the URI
func fetchJWKS(jwksURI string) (*JWKS, error) {
	resp, err := http.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	return &jwks, nil
}
