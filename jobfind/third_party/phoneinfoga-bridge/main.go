// Structured output from the pinned upstream scanners; no server or web client.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sundowndev/phoneinfoga/v2/lib/number"
	"github.com/sundowndev/phoneinfoga/v2/lib/remote"
	"github.com/sundowndev/phoneinfoga/v2/lib/remote/suppliers"
)

type result struct {
	State  string      `json:"state"`
	Data   interface{} `json:"data,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

// Upstream suppliers instantiate their own clients. Bound and route all of them.
type transport struct {
	base   http.RoundTripper
	ctx    context.Context
	status int
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(t.ctx)
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("HTTPS required")
	}
	host := r.URL.Hostname()
	if host != "api.apilayer.com" && host != "api.ovh.com" && host != "customsearch.googleapis.com" {
		return nil, fmt.Errorf("Unexpected upstream host")
	}
	if host != "api.apilayer.com" {
		r.Header.Del("Apikey")
	}
	r.Header.Del("X-Goog-Api-Key")
	if r.URL.Hostname() == "customsearch.googleapis.com" {
		r.Header.Set("X-Goog-Api-Key", os.Getenv("GOOGLE_API_KEY"))
	}
	response, err := t.base.RoundTrip(r)
	if err == nil {
		t.status = response.StatusCode
		if response.StatusCode >= 400 {
			response.Body.Close()
			return nil, fmt.Errorf("HTTP %d", response.StatusCode)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 2_000_001))
		response.Body.Close()
		if readErr != nil || len(body) > 2_000_000 {
			return nil, fmt.Errorf("Invalid or oversized upstream response")
		}
		if host == "api.apilayer.com" {
			var payload map[string]interface{}
			if json.Unmarshal(body, &payload) != nil {
				return nil, fmt.Errorf("Invalid provider response")
			}
			if _, valid := payload["valid"].(bool); !valid {
				return nil, fmt.Errorf("Missing provider validity field")
			}
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
	}
	return response, err
}

func scan(name, input string) (out result) {
	out = result{State: "error", Detail: "Scanner failed"}
	defer func() {
		if recover() != nil {
			out = result{State: "error", Detail: "Upstream scanner failed"}
		}
	}()
	if !regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`).MatchString(input) || !number.IsValid(input) {
		return result{State: "error", Detail: "Invalid international phone number"}
	}
	n, err := number.NewNumber(input)
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base := http.DefaultTransport.(*http.Transport).Clone()
	if proxy := os.Getenv("JOBFIND_ACTIVE_PROXY"); proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || u.Host == "" {
			return result{State: "error", Detail: "Invalid configured proxy"}
		}
		base.Proxy = http.ProxyURL(u)
	}
	t := &transport{base: base, ctx: ctx}
	previous := http.DefaultTransport
	http.DefaultTransport = t
	defer func() { http.DefaultTransport = previous; base.CloseIdleConnections() }()
	var s remote.Scanner
	switch name {
	case "local":
		s = remote.NewLocalScanner()
	case "googlesearch":
		s = remote.NewGoogleSearchScanner()
	case "numverify":
		s = remote.NewNumverifyScanner(suppliers.NewNumverifySupplier())
	case "ovh":
		s = remote.NewOVHScanner(suppliers.NewOVHSupplier())
	case "googlecse":
		os.Setenv("GOOGLECSE_MAX_RESULTS", "10")
		s = remote.NewGoogleCSEScanner(&http.Client{Transport: t, Timeout: 20 * time.Second})
	default:
		return result{State: "error", Detail: "Unknown scanner"}
	}
	opts := remote.ScannerOptions{}
	if s.DryRun(*n, opts) != nil {
		return result{State: "skipped", Detail: "Required credentials or supported country unavailable"}
	}
	data, err := s.Run(*n, opts)
	if err != nil {
		if ctx.Err() != nil {
			return result{State: "timeout", Detail: "Scanner exceeded 20 seconds"}
		}
		if t.status >= 400 {
			state := "error"
			if t.status == 401 || t.status == 403 || t.status == 429 {
				state = "blocked"
			}
			return result{State: state, Detail: fmt.Sprintf("HTTP %d", t.status)}
		}
		return result{State: "error", Detail: "Upstream request or response failed"}
	}
	return result{State: "ok", Data: data}
}

func main() {
	logrus.SetOutput(io.Discard)
	out := result{State: "error", Detail: "Expected scanner and international number"}
	if len(os.Args) == 3 {
		out = scan(os.Args[1], os.Args[2])
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
}
