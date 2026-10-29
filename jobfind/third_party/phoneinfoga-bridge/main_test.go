package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sundowndev/phoneinfoga/v2/lib/number"
	"github.com/sundowndev/phoneinfoga/v2/lib/remote"
	"github.com/sundowndev/phoneinfoga/v2/lib/remote/suppliers"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfflineAndInvalid(t *testing.T) {
	if got := scan("local", "+12025550123"); got.State != "ok" {
		t.Fatal(got)
	}
	if got := scan("googlesearch", "+12025550123"); got.State != "ok" {
		t.Fatal(got)
	}
	if got := scan("local", "+01234567890"); got.State != "error" {
		t.Fatal(got)
	}
	if got := scan("ovh", "+12025550123"); got.State != "skipped" {
		t.Fatal(got)
	}
	t.Setenv("NUMVERIFY_API_KEY", "")
	if got := scan("numverify", "+12025550123"); got.State != "skipped" {
		t.Fatal(got)
	}
}

func TestUpstreamProvidersWithFixtureHTTP(t *testing.T) {
	t.Setenv("GOOGLE_API_KEY", "fixture-secret")
	t.Setenv("GOOGLECSE_CX", "fixture-cx")
	t.Setenv("NUMVERIFY_API_KEY", "fixture-secret")
	n, _ := number.NewNumber("+12025550123")
	requests := 0
	guard := &transport{ctx: context.Background(), base: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		body := `{"valid":true,"number":"12025550123","country_code":"US"}`
		if r.URL.Hostname() == "customsearch.googleapis.com" {
			if r.Header.Get("X-Goog-Api-Key") != "fixture-secret" {
				t.Fatal("API key missing")
			}
			body = `{"searchInformation":{"totalResults":"1"},"items":[{"title":"Fixture","link":"https://example.org/contact"}]}`
		} else if r.Header.Get("Apikey") != "fixture-secret" {
			t.Fatal("Numverify key missing")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	previous := http.DefaultTransport
	http.DefaultTransport = guard
	defer func() { http.DefaultTransport = previous }()
	data, err := remote.NewNumverifyScanner(suppliers.NewNumverifySupplier()).Run(*n, remote.ScannerOptions{})
	if err != nil || !data.(remote.NumverifyScannerResponse).Valid {
		t.Fatalf("Numverify: %v", err)
	}
	data, err = remote.NewGoogleCSEScanner(&http.Client{Transport: guard}).Run(*n, remote.ScannerOptions{})
	if err != nil || data.(remote.GoogleCSEScannerResponse).ResultCount != 2 {
		t.Fatalf("CSE: %v", err)
	}
	if requests != 3 {
		t.Fatalf("Unexpected request count %d", requests)
	}
}

func TestTransportDoesNotExposeBlockedBodies(t *testing.T) {
	guard := &transport{ctx: context.Background(), base: fixtureTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("private-response-body"))}, nil
	})}
	request, _ := http.NewRequest("GET", "https://api.apilayer.com/test", nil)
	_, err := guard.RoundTrip(request)
	if err == nil || err.Error() != "HTTP 403" || guard.status != 403 {
		t.Fatalf("Unsafe error: %v", err)
	}
	request, _ = http.NewRequest("GET", "http://example.org/test", nil)
	if _, err = guard.RoundTrip(request); err == nil {
		t.Fatal("Allowed plaintext")
	}
	request, _ = http.NewRequest("GET", "https://example.org/redirect", nil)
	if _, err = guard.RoundTrip(request); err == nil {
		t.Fatal("Allowed credential redirect")
	}
}

func TestMalformedNumverifyIsNotNegativeEvidence(t *testing.T) {
	guard := &transport{ctx: context.Background(), base: fixtureTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"message":"unexpected response"}`))}, nil
	})}
	request, _ := http.NewRequest("GET", "https://api.apilayer.com/number_verification/validate", nil)
	if _, err := guard.RoundTrip(request); err == nil {
		t.Fatal("Malformed provider response became a validity result")
	}
}
