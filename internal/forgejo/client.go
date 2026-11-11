package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBody = 4 << 20

type Client struct {
	base        *url.URL
	token       string
	http        *http.Client
	retries     int
	rateMu      sync.Mutex
	nextRequest time.Time
	minInterval time.Duration
}

type Option func(*Client)

func WithHTTPClient(v *http.Client) Option { return func(c *Client) { c.http = v } }
func WithRetries(v int) Option             { return func(c *Client) { c.retries = v } }
func WithRateLimit(requestsPerSecond int) Option {
	return func(c *Client) {
		if requestsPerSecond > 0 {
			c.minInterval = time.Second / time.Duration(requestsPerSecond)
		}
	}
}

func New(rawURL, token string, opts ...Option) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(rawURL, "/") + "/api/v1/")
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("invalid Forgejo API URL")
	}
	c := &Client{base: base, token: token, retries: 3, minInterval: 100 * time.Millisecond, http: &http.Client{Timeout: 15 * time.Second}}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Forgejo API returned %d: %s", e.StatusCode, e.Message)
}

func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, method, path, in, out, func(req *http.Request) {
		req.Header.Set("Authorization", "token "+c.token)
	})
}

// DoSudo performs a user operation with a site administrator's API token.
// Forgejo 17 applies Sudo before resolving the /user routes.
func (c *Client) DoSudo(ctx context.Context, method, path, user string, in, out any) error {
	return c.do(ctx, method, path, in, out, func(req *http.Request) {
		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Sudo", user)
	})
}

// DoBasic is reserved for Forgejo operations, such as token creation, that
// explicitly require password authentication (the target account's, or a site
// administrator's) instead of an admin token.
func (c *Client) DoBasic(ctx context.Context, method, path, username, password string, in, out any) error {
	return c.do(ctx, method, path, in, out, func(req *http.Request) {
		req.SetBasicAuth(username, password)
	})
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, authenticate func(*http.Request)) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
	}
	endpoint, err := c.base.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return errors.New("invalid Forgejo API path")
	}
	for attempt := 0; ; attempt++ {
		if err := c.waitRate(ctx); err != nil {
			return err
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
		if reqErr != nil {
			return errors.New("construct Forgejo API request")
		}
		req.Header.Set("Accept", "application/json")
		authenticate(req)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, doErr := c.http.Do(req)
		if doErr != nil {
			if attempt < c.retries && ctx.Err() == nil {
				if err := wait(ctx, attempt, 0); err != nil {
					return err
				}
				continue
			}
			return errors.New("Forgejo API request failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if readErr != nil {
			return errors.New("read Forgejo API response")
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < c.retries {
			retryAfter, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			if err := wait(ctx, attempt, time.Duration(retryAfter)*time.Second); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			message := http.StatusText(resp.StatusCode)
			// Never include the URL, request, headers, or response body: Forgejo
			// may echo credential-bearing fields in validation errors.
			return &APIError{StatusCode: resp.StatusCode, Message: message}
		}
		if out != nil && len(data) != 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return errors.New("decode Forgejo API response")
			}
		}
		return nil
	}
}

func (c *Client) waitRate(ctx context.Context) error {
	c.rateMu.Lock()
	now := time.Now()
	waitFor := time.Duration(0)
	if now.Before(c.nextRequest) {
		waitFor = c.nextRequest.Sub(now)
	}
	c.nextRequest = now.Add(waitFor).Add(c.minInterval)
	c.rateMu.Unlock()
	if waitFor == 0 {
		return nil
	}
	timer := time.NewTimer(waitFor)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func wait(ctx context.Context, attempt int, retryAfter time.Duration) error {
	delay := time.Duration(1<<min(attempt, 4)) * 100 * time.Millisecond
	if retryAfter > delay {
		delay = retryAfter
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
