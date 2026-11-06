package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func init() { retryBackoff = time.Millisecond }

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing bearer token, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"code":"ERR_DUPLICATE_VALUE","message":"value already exists","path":"name"}]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateRole(context.Background(), RoleCreateRequest{Name: "x"})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 400 || !apiErr.HasCode("ERR_DUPLICATE_VALUE") {
		t.Fatalf("unexpected error: %+v", apiErr)
	}
	want := "api error: HTTP 400: ERR_DUPLICATE_VALUE: value already exists (name)"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
}

func TestRetryOnTooManyRequests(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":"role-A","name":"a","firewallRules":[]},"metadata":{}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	role, err := c.GetRole(context.Background(), "role-A")
	if err != nil {
		t.Fatal(err)
	}
	if role.ID != "role-A" || calls.Load() != 2 {
		t.Fatalf("got role %+v after %d calls", role, calls.Load())
	}
}

func TestRetryPolicyByMethod(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c, err := New(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.CreateRole(context.Background(), RoleCreateRequest{Name: "x"}); err == nil {
		t.Fatal("expected error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("POST was sent %d times, want 1", got)
	}

	calls.Store(0)
	if _, err := c.GetRole(context.Background(), "role-A"); err == nil {
		t.Fatal("expected error")
	}
	if got := calls.Load(); got != maxAttempts {
		t.Fatalf("GET was sent %d times, want %d", got, maxAttempts)
	}
}

// flakyTransport fails the first fails round trips with a transport error.
type flakyTransport struct {
	fails, calls int
}

func (t *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls++
	if t.calls <= t.fails {
		return nil, errors.New("connection reset by peer")
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestRetryOnTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"role-A","name":"a","firewallRules":[]},"metadata":{}}`))
	}))
	defer srv.Close()

	tr := &flakyTransport{fails: 1}
	c, err := New(srv.URL, "k", WithHTTPClient(&http.Client{Transport: tr}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRole(context.Background(), "role-A"); err != nil {
		t.Fatal(err)
	}
	if tr.calls != 2 {
		t.Fatalf("GET was sent %d times, want 2", tr.calls)
	}

	tr.calls = 0
	if _, err := c.CreateRole(context.Background(), RoleCreateRequest{Name: "x"}); err == nil {
		t.Fatal("expected error")
	}
	if tr.calls != 1 {
		t.Fatalf("POST was sent %d times, want 1", tr.calls)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("", ""); err == nil {
		t.Fatal("expected error for missing api key")
	}
	if _, err := New("not a url", "k"); err == nil {
		t.Fatal("expected error for bad endpoint")
	}
	c, err := New("", "k")
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint != DefaultEndpoint {
		t.Fatalf("got endpoint %q", c.endpoint)
	}
}

func TestNoRetryOnTLSError(t *testing.T) {
	// httptest's certificate is not trusted by the default transport.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tr := &flakyTransport{}
	c, err := New(srv.URL, "k", WithHTTPClient(&http.Client{Transport: tr}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRole(context.Background(), "role-A"); err == nil {
		t.Fatal("expected TLS error")
	}
	if tr.calls != 1 {
		t.Fatalf("GET was sent %d times, want 1", tr.calls)
	}
}

func TestAPIErrorNamesOverrideKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[` +
			`{"code":"ERR_INVALID_VALUE","message":"must be an allowed override option","path":"configOverrides[1].key"},` +
			`{"code":"ERR_INVALID_VALUE","message":"bad","path":"configOverrides[0].value"},` +
			`{"code":"ERR_INVALID_VALUE","message":"bad","path":"configOverrides[9].key"}]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.UpdateTag(context.Background(), "t", TagUpdateRequest{ConfigOverrides: []ConfigOverride{
		{Key: "logging.level", Value: []byte(`"secret"`)},
		{Key: "dns.resolver_addrs", Value: []byte(`[]`)},
	}})
	want := `api error: HTTP 400: ERR_INVALID_VALUE: must be an allowed override option (configOverrides[1].key "dns.resolver_addrs"); ` +
		`ERR_INVALID_VALUE: bad (configOverrides[0].value); ERR_INVALID_VALUE: bad (configOverrides[9].key)`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
