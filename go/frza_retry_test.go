package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withFastRetries(t *testing.T) {
	t.Helper()
	old := retryBackoffs
	retryBackoffs = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryBackoffs = old })
}

// TestResponsesRetry429ThenSuccess: 429 twice, then a valid stream — the
// caller must succeed and report attempts via onReasoning.
func TestResponsesRetry429ThenSuccess(t *testing.T) {
	withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"slow down"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n")
		fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
	}))
	defer srv.Close()

	var retries []string
	res, err := callOpenAIResponses(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "test-model", "key", srv.URL, nil, nil,
		func(s string) { retries = append(retries, s) })
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if res.Text != "ok" {
		t.Errorf("text = %q", res.Text)
	}
	if calls.Load() != 3 {
		t.Errorf("server calls = %d, want 3", calls.Load())
	}
	if len(retries) != 2 {
		t.Errorf("retry heartbeats = %d, want 2", len(retries))
	}
}

// TestResponsesRetryAuthFailsFast: 401 must not be retried.
func TestResponsesRetryAuthFailsFast(t *testing.T) {
	withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"bad key"}`)
	}))
	defer srv.Close()

	_, err := callOpenAIResponses(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("auth failure was retried: calls = %d", calls.Load())
	}
}

// TestResponsesRetryExhausted: persistent 500 gives up after the backoff list.
func TestResponsesRetryExhausted(t *testing.T) {
	withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	_, err := callOpenAIResponses(context.Background(),
		[]Message{{Role: "user", Content: "hi"}}, "", "m", "key", srv.URL, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("expected exhausted-retry error, got %v", err)
	}
	if calls.Load() != int32(len(retryBackoffs)+1) {
		t.Errorf("calls = %d, want %d", calls.Load(), len(retryBackoffs)+1)
	}
}
