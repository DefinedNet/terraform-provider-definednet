package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

// jsonencode() sorts keys and HTML-escapes like json.Marshal, so canonicalJSON
// must match it byte for byte or imports drift.
func TestCanonicalJSON(t *testing.T) {
	want, _ := json.Marshal(map[string]any{"b": "<a&b>", "a": 1})
	if !strings.Contains(string(want), `u003c`) {
		t.Fatal("json.Marshal did not HTML-escape; test premise broken")
	}
	got := canonicalJSON(json.RawMessage(`{"b": "<a&b>", "a": 1}`))
	if got != string(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}
