package vulndb

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDoWithRetry_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDoWithRetry_ClientError_NoRetry(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	// 4xx should not be retried
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt for 4xx, got %d", attempts.Load())
	}
}

func TestDoWithRetry_429_Retries(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}
}

func TestDoWithRetry_AllRetries_Fail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	_, err := doWithRetry(client, req, 1)
	if err == nil {
		t.Error("expected error after all retries exhausted")
	}
}

func TestDoWithRetry_DefaultMaxRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	// maxRetries <= 0 should use default
	resp, err := doWithRetry(client, req, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
