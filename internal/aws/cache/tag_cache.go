package cache

import (
	"sync"
	"time"
)

// TagCache provides thread-safe caching for resource tags
type TagCache struct {
	mu      sync.RWMutex
	cache   map[string]map[string]string
	expires map[string]time.Time
	ttl     time.Duration
}

// NewTagCache creates a new tag cache with specified TTL
func NewTagCache(ttl time.Duration) *TagCache {
	return &TagCache{
		cache:   make(map[string]map[string]string),
		expires: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// Get retrieves tags for a resource ARN
func (tc *TagCache) Get(arn string) (map[string]string, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	// Check if cached and not expired
	if expiry, exists := tc.expires[arn]; exists {
		if time.Now().Before(expiry) {
			if tags, ok := tc.cache[arn]; ok {
				return tags, true
			}
		}
	}

	return nil, false
}

// Set stores tags for a resource ARN
func (tc *TagCache) Set(arn string, tags map[string]string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache[arn] = tags
	tc.expires[arn] = time.Now().Add(tc.ttl)
}

// Clear removes all cached entries
func (tc *TagCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache = make(map[string]map[string]string)
	tc.expires = make(map[string]time.Time)
}

// Size returns the number of cached entries
func (tc *TagCache) Size() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	return len(tc.cache)
}

// CleanExpired removes expired cache entries
func (tc *TagCache) CleanExpired() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	for arn, expiry := range tc.expires {
		if now.After(expiry) {
			delete(tc.cache, arn)
			delete(tc.expires, arn)
		}
	}
}