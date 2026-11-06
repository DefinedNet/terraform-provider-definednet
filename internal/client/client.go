// Package client is a minimal HTTP client for the Defined Networking API,
// covering the endpoints the Terraform provider manages.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	// Key is the config override key at Path when Path names one, so the error
	// says which override it is about instead of only its index.
	Key string `json:"-"`
}

// APIError is returned for any non-2xx response.
type APIError struct {
	StatusCode int
	Errors     []ErrorDetail
	Body       string
	// RequestID is the API's X-Request-ID, which support can use to find the
	// request in server logs.
	RequestID string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("api error: HTTP %d", e.StatusCode)
	if len(e.Errors) == 0 {
		if body := strings.TrimSpace(e.Body); body != "" {
			s += ": " + body
		}
	} else {
		parts := make([]string, 0, len(e.Errors))
		for _, d := range e.Errors {
			p := d.Code
			if d.Message != "" {
				p += ": " + d.Message
			}
			if d.Path != "" {
				if d.Key != "" {
					p += fmt.Sprintf(" (%s %q)", d.Path, d.Key)
				} else {
					p += " (" + d.Path + ")"
				}
			}
			parts = append(parts, p)
		}
		s += ": " + strings.Join(parts, "; ")
	}
	if e.RequestID != "" {
		s += " (request id " + e.RequestID + ")"
	}
	return s
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

const maxAttempts = 4

// retryBackoff is multiplied by the attempt number between retries. It is a
// variable so tests can shorten it.
var retryBackoff = 2 * time.Second

// do performs a request, retrying on 429 and on 5xx for idempotent methods,
// and decodes the data envelope into out when out is non-nil. It returns the
// raw metadata.
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
			// Same POST rule as the 5xx case below: the connection can drop
			// after the server committed the create.
			if method == http.MethodPost || attempt == maxAttempts || permanentTransportError(err) {
				return nil, err
			}
			lastErr = err
			if err := wait(ctx, attempt); err != nil {
				return nil, err
			}
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
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

		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(respBody), RequestID: resp.Header.Get("X-Request-ID")}
		var errEnv struct {
			Errors []ErrorDetail `json:"errors"`
		}
		if json.Unmarshal(respBody, &errEnv) == nil {
			apiErr.Errors = errEnv.Errors
			for i, d := range apiErr.Errors {
				apiErr.Errors[i].Key = overrideKeyAt(payload, d.Path)
			}
		}
		lastErr = apiErr

		// A 5xx on POST may arrive after the server committed the create.
		// Creates have no idempotency key, so a retry would fail on the
		// unique name and leave the created object outside Terraform state.
		retryable := resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode >= 500 && method != http.MethodPost)
		if !retryable || attempt == maxAttempts {
			return nil, apiErr
		}

		if err := wait(ctx, attempt); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

// overrideKeyPath matches the error path of a config override key in a tag
// (configOverrides) or network (overrides) request body. Other fields are
// never echoed, since they can be secrets.
var overrideKeyPath = regexp.MustCompile(`^(configOverrides|overrides)\[(\d+)\]\.key$`)

// overrideKeyAt returns the config override key the error path points at in
// the request body, or "" if the path is not an override key.
func overrideKeyAt(payload []byte, path string) string {
	m := overrideKeyPath.FindStringSubmatch(path)
	if m == nil {
		return ""
	}
	var body map[string]json.RawMessage
	var overrides []ConfigOverride
	if json.Unmarshal(payload, &body) != nil || json.Unmarshal(body[m[1]], &overrides) != nil {
		return ""
	}
	i, _ := strconv.Atoi(m[2])
	if i >= len(overrides) {
		return ""
	}
	return overrides[i].Key
}

// permanentTransportError reports a failure no retry can fix. Like
// go-retryablehttp, only TLS verification is treated as permanent; DNS and
// connection failures are often transient under resolver or LB restarts.
func permanentTransportError(err error) bool {
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

// wait sleeps for the attempt's backoff unless ctx ends first.
func wait(ctx context.Context, attempt int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(retryBackoff * time.Duration(attempt)):
		return nil
	}
}

// pathSegment escapes a value for use as a single URL path segment. Tag names
// contain a colon, which is legal in a path segment and which chi decodes either way.
func pathSegment(s string) string {
	return url.PathEscape(s)
}
