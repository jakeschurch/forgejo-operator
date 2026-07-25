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
	"time"
)

const maxBody = 4 << 20

type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	retries int
}

type Option func(*Client)

func WithHTTPClient(v *http.Client) Option { return func(c *Client) { c.http = v } }
func WithRetries(v int) Option             { return func(c *Client) { c.retries = v } }

func New(rawURL, token string, opts ...Option) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(rawURL, "/") + "/api/v1/")
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("invalid Forgejo API URL")
	}
	c := &Client{base: base, token: token, retries: 3, http: &http.Client{Timeout: 15 * time.Second}}
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
		req, reqErr := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
		if reqErr != nil {
			return errors.New("construct Forgejo API request")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "token "+c.token)
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
			var payload struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(data, &payload) == nil && payload.Message != "" {
				message = payload.Message
			}
			// Never include the URL, request, headers, or raw response: any can contain credentials.
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
