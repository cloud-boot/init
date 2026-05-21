package main

// OpenStack Keystone v3 application-credential (AC) authentication.
//
// An AC is a long-lived (id, secret) pair that maps to a specific
// project + role assignment in Keystone. POSTing the pair to
// /v3/auth/tokens returns a short-lived bearer token in the
// X-Subject-Token response header — usable as Authorization:
// Bearer for any OpenStack API (Glance image read, Nova metadata
// proxy, Keystone-protected metadata stores, …) and for OCI
// registries that accept Keystone tokens (Harbor with the
// keystone-auth plugin, OpenStack-glance container artifacts).
//
// Cmdline knobs:
//
//	cloudboot.openstack.auth-url=<https://...:5000/v3>
//	cloudboot.openstack.app-cred-id=<uuid>
//	cloudboot.openstack.app-cred-secret=<secret>
//
// Workflow at boot (called from main.go, after network bringup):
//
//	if all three knobs are set →
//	  POST {auth_url}/auth/tokens with the AC creds →
//	  capture the X-Subject-Token header →
//	  inject as cloudboot.metadata.token so the downstream
//	  metadata + OCI fetch paths reuse it as Bearer auth.
//
// Security: the AC secret in /proc/cmdline is visible to anyone
// with read access to /proc on the running staged distro
// (typically root). For production this should be replaced by
// a file-backed source (cidata mount, vendor_data fetch with
// IP-gated trust) — the current cmdline knob is fine for the
// initial OCI-pull + metadata-fetch window, since cloud-boot
// reboots into a different kernel that owns the post-reboot
// cmdline. See memory:subplan-and-metadata for the roadmap.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// keystoneAuthRequest mirrors the JSON body Keystone v3 expects on
// POST /v3/auth/tokens with the application_credential method.
// Project / domain scoping is implicit in the AC itself (Keystone
// derives them from the AC's owner) so we don't supply them here.
type keystoneAuthRequest struct {
	Auth struct {
		Identity struct {
			Methods               []string `json:"methods"`
			ApplicationCredential struct {
				ID     string `json:"id"`
				Secret string `json:"secret"`
			} `json:"application_credential"`
		} `json:"identity"`
	} `json:"auth"`
}

// fetchKeystoneToken exchanges an application credential for a
// Keystone token. Returns the X-Subject-Token header value on
// success — that's what you set as Authorization: Bearer for
// subsequent OpenStack API calls.
//
// authURL is the Keystone v3 root (e.g.
// "https://keystone.example.com:5000/v3"). The function appends
// "/auth/tokens" itself so the operator just hands us the
// service-discovery URL from openrc / vendor_data.
func fetchKeystoneToken(authURL, acID, acSecret string) (string, error) {
	if acID == "" || acSecret == "" {
		return "", fmt.Errorf("application-credential id/secret required")
	}
	url := strings.TrimRight(authURL, "/") + "/auth/tokens"

	var req keystoneAuthRequest
	req.Auth.Identity.Methods = []string{"application_credential"}
	req.Auth.Identity.ApplicationCredential.ID = acID
	req.Auth.Identity.ApplicationCredential.Secret = acSecret

	body, err := json.Marshal(&req)
	if err != nil {
		return "", fmt.Errorf("marshal auth body: %w", err)
	}
	hreq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(hreq)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		// Drain a bit of the body for the error message — Keystone
		// gives a useful JSON error here (invalid credential,
		// expired AC, project disabled, …) that's worth surfacing.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("keystone status %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	tok := resp.Header.Get("X-Subject-Token")
	if tok == "" {
		return "", fmt.Errorf("keystone returned 201 but no X-Subject-Token header")
	}
	return tok, nil
}
