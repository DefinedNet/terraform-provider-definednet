package client

import (
	"context"
	"encoding/json"
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

// The PATCH body must tell "leave unchanged" (omitted) from "remove" (null).
func TestJoinKeyPatchRequestJSON(t *testing.T) {
	name := "k"
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var none *time.Time
	for _, tc := range []struct {
		req  JoinKeyPatchRequest
		want string
	}{
		{JoinKeyPatchRequest{}, `{}`},
		{JoinKeyPatchRequest{Name: &name}, `{"name":"k"}`},
		{JoinKeyPatchRequest{ExpiresAt: &none}, `{"expiresAt":null}`},
		{JoinKeyPatchRequest{ExpiresAt: func() **time.Time { p := &at; return &p }()}, `{"expiresAt":"2030-01-02T03:04:05Z"}`},
	} {
		got, err := json.Marshal(tc.req)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}
