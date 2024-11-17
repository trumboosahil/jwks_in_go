package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CacheConfig defines cache settings for the JWKS client
type CacheConfig struct {
	CacheEnabled    bool          // Enable or disable caching
	CacheMaxEntries int           // Maximum number of cached keys
	CacheMaxAge     time.Duration // Maximum age for cached keys
}

// JWKSClient is the main struct for the JWKS library
type JWKSClient struct {
	issuer  string
	jwksURI string
	cache   *keyCache
	mu      sync.RWMutex
}

// NewClient creates a new JWKS client with dynamic JWKS URI discovery
func NewClient(issuer string, cacheConfig CacheConfig) (*JWKSClient, error) {
	jwksURI, err := fetchJWKSURI(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS URI: %w", err)
	}

	var cache *keyCache
	if cacheConfig.CacheEnabled {
		cache = newKeyCache(cacheConfig)
	}

	return &JWKSClient{
		issuer:  issuer,
		jwksURI: jwksURI,
		cache:   cache,
	}, nil
}

// GetPublicKey retrieves a public key by "kid" and converts it to an *rsa.PublicKey
func (c *JWKSClient) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check cache if enabled
	if c.cache != nil {
		if key, exists := c.cache.get(kid); exists {
			if rsaKey, ok := key.(*rsa.PublicKey); ok {
				return rsaKey, nil
			}
			return nil, errors.New("cached key is not of type *rsa.PublicKey")
		}
	}

	// Fetch keys using the existing fetchJWKS function
	jwks, err := fetchJWKS(c.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Find the matching key by "kid"
	var matchingKey map[string]interface{}
	for _, key := range jwks.Keys {
		if key["kid"] == kid {
			matchingKey = key
			break
		}
	}

	if matchingKey == nil {
		return nil, errors.New("key not found in JWKS")
	}

	// Convert the matching key to an *rsa.PublicKey
	rsaKey, err := parseRSAPublicKey(matchingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	// Cache the key if caching is enabled
	if c.cache != nil {
		c.cache.set(kid, rsaKey)
	}

	return rsaKey, nil
}

// GetPublicKeyFromToken retrieves the public key for the provided JWT token string
func (c *JWKSClient) GetPublicKeyFromToken(tokenString string) (*rsa.PublicKey, error) {
	// Parse the token without validation to extract the header
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract "kid" from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("missing kid in token header")
	}

	// Fetch the public key using the "kid"
	return c.GetPublicKey(kid)
}

// GetKeyFunc returns a KeyFunc that can be used with jwt.Parse to fetch public keys dynamically
func (c *JWKSClient) GetKeyFunc() jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		// Extract "kid" from the token header
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}
		// Fetch the public key
		return c.GetPublicKey(kid)
	}
}

// parseRSAPublicKey converts a JWKS key (map[string]interface{}) to an *rsa.PublicKey
func parseRSAPublicKey(jwksKey map[string]interface{}) (*rsa.PublicKey, error) {
	// Extract modulus (n) and exponent (e)
	nStr, okN := jwksKey["n"].(string)
	eStr, okE := jwksKey["e"].(string)
	if !okN || !okE {
		return nil, errors.New("invalid JWKS key: missing 'n' or 'e'")
	}

	// Decode base64url fields
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus (n): %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent (e): %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)

	// Exponent is usually small, so convert directly to int
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	// Construct the RSA public key
	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
