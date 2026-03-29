package vulndb

import (
	"fmt"
	"math"
	"net/http"
	"time"
)

const (
	defaultMaxRetries = 3
	defaultBaseDelay  = 2 * time.Second
)

// doWithRetry executes an HTTP request with exponential backoff retry on
// transient errors (5xx status codes, connection errors).
func doWithRetry(client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}

	var lastErr error
	for attempt := range maxRetries {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			backoff(attempt)
			continue
		}

		// Retry on 5xx server errors and 429 rate limit.
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			backoff(attempt)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

func backoff(attempt int) {
	delay := defaultBaseDelay * time.Duration(math.Pow(2, float64(attempt)))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	time.Sleep(delay)
}
