package forgejo

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestAndRedaction(t *testing.T) {
	const token = "never-print-this"
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "token "+token {
			t.Errorf("authorization = %q", got)
		}
		return response(http.StatusUnauthorized, `{"message":"denied"}`), nil
	})
	c, err := New("https://forgejo.invalid", token, WithRetries(0), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Do(context.Background(), http.MethodGet, "user", nil, nil)
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "forgejo.invalid") {
		t.Fatalf("error is absent or leaks credentials: %v", err)
	}
}

func TestBoundedRetry(t *testing.T) {
	var calls atomic.Int32
	transport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		if calls.Add(1) < 3 {
			return response(http.StatusServiceUnavailable, "temporary"), nil
		}
		return response(http.StatusOK, `{"ok":true}`), nil
	})
	c, _ := New("https://forgejo.invalid", "token", WithRetries(3), WithHTTPClient(&http.Client{Transport: transport}))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out map[string]bool
	if err := c.Do(ctx, http.MethodGet, "version", nil, &out); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || !out["ok"] {
		t.Fatalf("calls=%d out=%v", calls.Load(), out)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
