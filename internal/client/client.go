// Package client is a minimal HTTP client for the Defined Networking API,
// covering the endpoints the Terraform provider manages.
package client

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

const DefaultEndpoint = "https://api.defined.net"

// Client talks to the Defined Networking API with a bearer API key.
type Client struct {
	endpoint   string
	apiKey     string
	userAgent  string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithUserAgent sets the User-Agent header sent with every request.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// New returns a Client for the given API endpoint and key.
func New(endpoint, apiKey string, opts ...Option) (*Client, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q: must be an http(s) URL", endpoint)
	}
	if apiKey == "" {
		return nil, errors.New("api key is required")
	}

	c := &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		apiKey:     apiKey,
		userAgent:  "terraform-provider-definednet",
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// ErrorDetail is one entry of the API's errors array.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// APIError is returned for any non-2xx response.
type APIError struct {
	StatusCode int
	Errors     []ErrorDetail
	Body       string
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		body := strings.TrimSpace(e.Body)
		if body == "" {
			return fmt.Sprintf("api error: HTTP %d", e.StatusCode)
		}
		return fmt.Sprintf("api error: HTTP %d: %s", e.StatusCode, body)
	}
	parts := make([]string, 0, len(e.Errors))
	for _, d := range e.Errors {
		s := d.Code
		if d.Message != "" {
			s += ": " + d.Message
		}
		if d.Path != "" {
			s += " (" + d.Path + ")"
		}
		parts = append(parts, s)
	}
	return fmt.Sprintf("api error: HTTP %d: %s", e.StatusCode, strings.Join(parts, "; "))
}

// HasCode reports whether any error detail carries the given code.
func (e *APIError) HasCode(code string) bool {
	for _, d := range e.Errors {
		if d.Code == code {
			return true
		}
	}
	return false
}

// IsNotFound reports whether err is an API 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

// response is the envelope every successful API response uses.
type response struct {
	Data     json.RawMessage `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
}

// PaginationMetadata is the metadata block of list responses.
type PaginationMetadata struct {
	HasNextPage bool   `json:"hasNextPage"`
	NextCursor  string `json:"nextCursor"`
}

const (
	maxAttempts    = 4
	defaultBackoff = 2 * time.Second
)

// do performs a request, retrying on 429 and 5xx, and decodes the data
// envelope into out when out is non-nil. It returns the raw metadata.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) (json.RawMessage, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
	}

	u := c.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var env response
			if len(respBody) > 0 {
				if err := json.Unmarshal(respBody, &env); err != nil {
					return nil, fmt.Errorf("decoding response envelope: %w", err)
				}
			}
			if out != nil && len(env.Data) > 0 {
				if err := json.Unmarshal(env.Data, out); err != nil {
					return nil, fmt.Errorf("decoding response data: %w", err)
				}
			}
			return env.Metadata, nil
		}

		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
		var errEnv struct {
			Errors []ErrorDetail `json:"errors"`
		}
		if json.Unmarshal(respBody, &errEnv) == nil {
			apiErr.Errors = errEnv.Errors
		}
		lastErr = apiErr

		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if !retryable || attempt == maxAttempts {
			return nil, apiErr
		}

		wait := defaultBackoff * time.Duration(attempt)
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, lastErr
}

// pathSegment escapes a value for use as a single URL path segment. Tag names
// contain a colon, which is legal in a path segment and which chi decodes either way.
func pathSegment(s string) string {
	return url.PathEscape(s)
}
