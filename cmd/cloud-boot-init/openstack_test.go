package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchKeystoneToken_Happy verifies the AC creds POST + the
// X-Subject-Token header capture against a mocked Keystone v3
// endpoint.
func TestFetchKeystoneToken_Happy(t *testing.T) {
	var gotBody keystoneAuthRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/auth/tokens" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("X-Subject-Token", "gAAAAA-fake-token-payload")
		w.WriteHeader(http.StatusCreated)
		// Keystone normally returns a token body too, but our
		// caller only needs the header.
	}))
	defer srv.Close()

	tok, err := fetchKeystoneToken(srv.URL+"/v3", "ac-uuid", "ac-sekrit")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "gAAAAA-fake-token-payload" {
		t.Errorf("token = %q", tok)
	}
	if gotBody.Auth.Identity.ApplicationCredential.ID != "ac-uuid" {
		t.Errorf("AC id = %q", gotBody.Auth.Identity.ApplicationCredential.ID)
	}
	if gotBody.Auth.Identity.ApplicationCredential.Secret != "ac-sekrit" {
		t.Errorf("AC secret = %q", gotBody.Auth.Identity.ApplicationCredential.Secret)
	}
	if len(gotBody.Auth.Identity.Methods) != 1 || gotBody.Auth.Identity.Methods[0] != "application_credential" {
		t.Errorf("methods = %v", gotBody.Auth.Identity.Methods)
	}
}

// TestFetchKeystoneToken_TrailingSlash confirms a trailing slash on
// the auth URL doesn't produce a //auth/tokens path — Keystone's
// own examples vary on whether the URL ends in / so we normalise.
func TestFetchKeystoneToken_TrailingSlash(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("X-Subject-Token", "t")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	if _, err := fetchKeystoneToken(srv.URL+"/v3/", "id", "s"); err != nil {
		t.Fatal(err)
	}
	if seenPath != "/v3/auth/tokens" {
		t.Errorf("path = %q, want /v3/auth/tokens", seenPath)
	}
}

// TestFetchKeystoneToken_EmptyCreds rejects empty AC fields up-front
// rather than hitting the wire with garbage.
func TestFetchKeystoneToken_EmptyCreds(t *testing.T) {
	if _, err := fetchKeystoneToken("http://x", "", "s"); err == nil {
		t.Error("expected error on empty id")
	}
	if _, err := fetchKeystoneToken("http://x", "id", ""); err == nil {
		t.Error("expected error on empty secret")
	}
}

// TestFetchKeystoneToken_AuthError surfaces Keystone's 401 body so
// the operator sees "invalid credential" rather than just a generic
// network error.
func TestFetchKeystoneToken_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}`))
	}))
	defer srv.Close()
	_, err := fetchKeystoneToken(srv.URL+"/v3", "id", "s")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention 401: %v", err)
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error should include keystone body: %v", err)
	}
}

// TestFetchKeystoneToken_NoHeader catches the weird case where
// Keystone returns 201 (success) but forgets the X-Subject-Token
// header — should be impossible against a real Keystone but
// defensive code is cheap.
func TestFetchKeystoneToken_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	_, err := fetchKeystoneToken(srv.URL+"/v3", "id", "s")
	if err == nil || !strings.Contains(err.Error(), "X-Subject-Token") {
		t.Errorf("expected missing-header error, got %v", err)
	}
}
