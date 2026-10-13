package client

import (
	"context"
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
