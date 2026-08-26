package capture

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

type webhookClient struct {
	url        string
	authHeader string
	client     *http.Client
}

// NewWebhook creates a webhook sender. tlsVerify=false is rejected; callers
// must pass true. TLS certificate verification is always enforced.
func NewWebhook(url, authHeader string, tlsVerify bool) (*webhookClient, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url must not be empty")
	}
	// Enforce TLS verification regardless of the config value.
	// We log a warning if the caller tried to disable it.
	if !tlsVerify {
		log.Printf("capture: webhook tls_verify=false ignored; TLS verification is always enforced")
	}
	return &webhookClient{
		url:        url,
		authHeader: authHeader,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}, nil
}

func (w *webhookClient) send(body []byte) {
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		log.Printf("capture: webhook new request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authHeader != "" {
		req.Header.Set("Authorization", w.authHeader)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("capture: webhook send: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("capture: webhook returned %d", resp.StatusCode)
	}
}
