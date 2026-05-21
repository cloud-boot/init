package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestApplyMetadataOverrides_Happy verifies the JSON document
// at the metadata URL gets its `cloudboot` block applied as
// cmdline overrides — both setting unset keys and overwriting
// existing ones.
func TestApplyMetadataOverrides_Happy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
		  "cloudboot": {
		    "plan":   "registry.example.com/boot/production:latest",
		    "target": "primary",
		    "keymap": "fr-mac"
		  },
		  "ignored":  "non-cloudboot keys are fine"
		}`)
	}))
	defer srv.Close()

	cmd := map[string]string{
		"cloudboot.keymap": "us", // will be overridden by metadata
	}
	if err := applyMetadataOverrides(srv.URL, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd["cloudboot.plan"] != "registry.example.com/boot/production:latest" {
		t.Errorf("plan = %q", cmd["cloudboot.plan"])
	}
	if cmd["cloudboot.target"] != "primary" {
		t.Errorf("target = %q", cmd["cloudboot.target"])
	}
	if cmd["cloudboot.keymap"] != "fr-mac" {
		t.Errorf("keymap = %q (override from us not applied)", cmd["cloudboot.keymap"])
	}
}

// TestApplyMetadataOverrides_BearerAuth confirms the
// cloudboot.metadata.token= cmdline knob is forwarded as a
// Bearer header — for private metadata endpoints behind a proxy.
func TestApplyMetadataOverrides_BearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"cloudboot":{}}`)
	}))
	defer srv.Close()

	cmd := map[string]string{"cloudboot.metadata.token": "sekrit"}
	if err := applyMetadataOverrides(srv.URL, cmd); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Errorf("Authorization header = %q, want Bearer sekrit", gotAuth)
	}
}

// TestApplyMetadataOverrides_NoCloudbootBlock should no-op cleanly
// when the JSON has no `cloudboot` key — typical of a generic
// metadata endpoint that also serves to other consumers.
func TestApplyMetadataOverrides_NoCloudbootBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"other": "stuff"}`)
	}))
	defer srv.Close()
	cmd := map[string]string{"cloudboot.plan": "pre-existing"}
	if err := applyMetadataOverrides(srv.URL, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd["cloudboot.plan"] != "pre-existing" {
		t.Errorf("plan unexpectedly modified: %q", cmd["cloudboot.plan"])
	}
}

// TestApplyMetadataOverrides_HTTPError surfaces 404/500 as errors
// so the caller can log + degrade gracefully.
func TestApplyMetadataOverrides_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such instance", http.StatusNotFound)
	}))
	defer srv.Close()
	err := applyMetadataOverrides(srv.URL, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 error, got %v", err)
	}
}

// TestApplyMetadataOverrides_BadJSON returns a parse error rather
// than crashing or silently swallowing bytes.
func TestApplyMetadataOverrides_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>not json</html>`)
	}))
	defer srv.Close()
	err := applyMetadataOverrides(srv.URL, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "parse JSON") {
		t.Errorf("expected parse-JSON error, got %v", err)
	}
}
