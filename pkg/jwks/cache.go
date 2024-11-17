package jwks

import (
	"sync"
	"time"
)

type keyCache struct {
	mu       sync.RWMutex
	keys     map[string]interface{}
	expiry   time.Time
	maxAge   time.Duration
	maxItems int
}

func newKeyCache(config CacheConfig) *keyCache {
	return &keyCache{
		keys:     make(map[string]interface{}),
		maxAge:   config.CacheMaxAge,
		maxItems: config.CacheMaxEntries,
	}
}

func (c *keyCache) get(kid string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if time.Now().After(c.expiry) {
		return nil, false
	}

	key, exists := c.keys[kid]
	return key, exists
}

func (c *keyCache) set(kid string, key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if over capacity
	if len(c.keys) >= c.maxItems {
		for k := range c.keys {
			delete(c.keys, k)
			break
		}
	}

	// Set the key and update expiry
	c.keys[kid] = key
	c.expiry = time.Now().Add(c.maxAge)
}
