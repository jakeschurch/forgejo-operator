package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeCacheSyncer func(context.Context) bool

func (f fakeCacheSyncer) WaitForCacheSync(ctx context.Context) bool { return f(ctx) }

func TestCacheReady(t *testing.T) {
	for _, name := range []string{"synced", "unsynced", "shutdown", "shutdown-during-sync", "request-canceled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			called := false
			cache := fakeCacheSyncer(func(probeCtx context.Context) bool {
				called = true
				switch name {
				case "unsynced", "request-canceled":
					<-probeCtx.Done()
					return false
				case "shutdown-during-sync":
					cancel()
				}
				return true
			})
			if name == "shutdown" {
				cancel()
			}
			if name == "request-canceled" {
				requestCtx, cancelRequest := context.WithCancel(request.Context())
				cancelRequest()
				request = request.WithContext(requestCtx)
			}
			start := time.Now()
			err := cacheReady(ctx, cache)(request)
			if name == "synced" && err != nil {
				t.Fatalf("synced cache: %v", err)
			}
			if name != "synced" && err == nil {
				t.Fatal("readiness unexpectedly passed")
			}
			if name == "shutdown" {
				if called {
					t.Fatal("shutdown must fail without waiting on cache")
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("shutdown = %v; want context.Canceled", err)
				}
			}
			if elapsed := time.Since(start); elapsed >= time.Second {
				t.Fatalf("readiness exceeded kubelet timeout: %s", elapsed)
			}
		})
	}
}
