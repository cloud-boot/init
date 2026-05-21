package main

// Metadata-driven cmdline overrides.
//
// `cloudboot.metadata.url=<url>` (read at boot) points init at any
// HTTP/HTTPS endpoint that returns a JSON document of the form:
//
//	{
//	    "cloudboot": {
//	        "plan":    "registry.example.com/boot/production:latest",
//	        "target":  "primary",
//	        "cmdline": "ip=dhcp ...",
//	        "keymap":  "fr-mac",
//	        "menu":    "0",
//	        "exit":    "reboot"
//	    }
//	}
//
// Each key under `cloudboot` becomes a cmdline knob override:
// `plan` → `cloudboot.plan`, `target` → `cloudboot.target`, etc.
// Anything outside the `cloudboot` map is ignored, so this is safe
// to point at a richer payload (e.g. OpenStack's user_data when
// it carries non-cloudboot cloud-init directives alongside ours).
//
// The override pattern is "metadata wins over cmdline" — the
// operator pushes a config to the metadata service and the VM
// picks it up next boot without rebuilding the boot.iso. That's
// the whole point of metadata.
//
// Auth: not handled here yet. For private metadata endpoints,
// pass a bearer token via `cloudboot.metadata.token=<...>` (sent
// as `Authorization: Bearer <token>`). A future iteration may
// add Keystone application-credential exchange so VMs can fetch
// a fresh token from OS_AUTH_URL using a long-lived AC id+secret
// stamped in vendor_data — see memory:uki-menu-then-reboot for
// the OpenStack roadmap.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// applyMetadataOverrides fetches the JSON document at url and
// applies its `cloudboot` block onto cmd. Returns nil on success
// (including the "no cloudboot block" case — a no-op is fine).
// Errors are NON-FATAL to the caller: a failed metadata fetch
// degrades to "use cmdline values" rather than refusing to boot.
func applyMetadataOverrides(url string, cmd map[string]string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// Bearer auth for private endpoints. The token can be
	// embedded in the iso cmdline OR (more typically) injected
	// by an outer service that proxies to a Keystone-protected
	// resource.
	if tok := cmd["cloudboot.metadata.token"]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	log.Printf("metadata: fetched %d bytes from %s", len(body), url)

	var doc struct {
		Cloudboot map[string]string `json:"cloudboot"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	if len(doc.Cloudboot) == 0 {
		log.Printf("metadata: no `cloudboot` block in payload — nothing to override")
		return nil
	}
	for k, v := range doc.Cloudboot {
		full := "cloudboot." + k
		old := cmd[full]
		cmd[full] = v
		if old == "" {
			log.Printf("metadata: %s=%q (was unset)", full, v)
		} else if old != v {
			log.Printf("metadata: %s=%q (overrides cmdline %q)", full, v, old)
		}
	}
	return nil
}
