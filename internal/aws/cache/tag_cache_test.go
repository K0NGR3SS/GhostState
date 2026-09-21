package cache

import (
	"sync"
	"testing"
	"time"
)

func TestCacheOwnsTagMaps(t *testing.T) {
	cache := NewTagCache(time.Minute)
	tags := map[string]string{"Owner": "original"}
	cache.Set("arn", tags)
	tags["Owner"] = "changed input"
	got, ok := cache.Get("arn")
	if !ok || got["Owner"] != "original" {
		t.Fatalf("caller changed cached data: %v", got)
	}
	got["Owner"] = "changed output"
	got, _ = cache.Get("arn")
	if got["Owner"] != "original" {
		t.Fatal("Get returned shared mutable data")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _ := cache.Get("arn")
			got["Owner"] = "local edit"
		}()
	}
	wg.Wait()
}

func TestExpiredEntriesAreNotReturned(t *testing.T) {
	cache := NewTagCache(-time.Second)
	cache.Set("arn", map[string]string{"Owner": "test"})
	if _, ok := cache.Get("arn"); ok {
		t.Fatal("returned expired entry")
	}
	cache.CleanExpired()
	if cache.Size() != 0 {
		t.Fatal("expired entry was not removed")
	}
}
