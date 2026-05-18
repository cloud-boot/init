// Package cosign verifies cosign-style OCI signatures against a static
// PKIX public key. It is intentionally limited to the simple-signing
// envelope (the deterministic, offline-verifiable case); keyless verification
// via Fulcio + Rekor is out of scope and tracked as a TODO.
//
// Wire-level flow
//
//   - Given an image manifest ref R, fetch the manifest bytes and digest D.
//   - Look up the signature manifest at R's repo, tag "<algo>-<hex>.sig"
//     (the cosign "legacy" tag scheme). The OCI 1.1 referrers API is not
//     used here; it requires extra server support and isn't ubiquitous yet.
//   - Pick the first layer whose mediaType is
//     application/vnd.dev.cosign.simplesigning.v1+json.
//   - Fetch that layer's blob — it is the "simple signing" JSON envelope.
//   - Base64-decode the annotation dev.cosignproject.cosign/signature on the
//     same layer descriptor and verify it against SHA-256 of the envelope
//     using the configured public key.
//   - Decode the envelope and confirm
//     critical.image.docker-manifest-digest == D.
package cosign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	digest "github.com/opencontainers/go-digest"

	"github.com/cloud-boot/init/pkg/oci"
)

const (
	mediaTypeSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	annotationSignature    = "dev.cosignproject.cosign/signature"
)

// Verifier holds a parsed public key.
type Verifier struct {
	PublicKey crypto.PublicKey
}

// ParsePublicKey accepts a PEM-encoded PKIX public key (the format produced
// by `cosign generate-key-pair`).
func ParsePublicKey(pemBytes []byte) (*Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("cosign: input is not PEM-encoded")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cosign: parse PKIX: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return &Verifier{PublicKey: pub}, nil
	default:
		return nil, fmt.Errorf("cosign: unsupported key type %T", pub)
	}
}

// Verify fetches the cosign signature for the manifest at ref, checks it
// against v.PublicKey, and confirms the signed digest matches the manifest's
// digest. It returns nil iff at least one usable signature layer verified.
func (v *Verifier) Verify(c *oci.Client, ref *oci.Ref) error {
	if v == nil {
		return nil
	}
	_, raw, err := c.PullManifest(ref)
	if err != nil {
		return fmt.Errorf("cosign: fetch manifest %s: %w", ref.Reference, err)
	}
	target := digest.FromBytes(raw)

	sigRef := *ref
	sigRef.Reference = fmt.Sprintf("%s-%s.sig", target.Algorithm(), target.Encoded())

	sigManifest, _, err := c.PullManifest(&sigRef)
	if err != nil {
		return fmt.Errorf("cosign: fetch signature %s: %w", sigRef.Reference, err)
	}

	var lastErr error
	for _, layer := range sigManifest.Layers {
		if layer.MediaType != mediaTypeSimpleSigning {
			continue
		}
		sigB64, ok := layer.Annotations[annotationSignature]
		if !ok || sigB64 == "" {
			lastErr = errors.New("simplesigning layer missing signature annotation")
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			lastErr = fmt.Errorf("decode signature: %w", err)
			continue
		}
		var body bytes.Buffer
		if _, err := c.PullBlob(&sigRef, layer.Digest, &body); err != nil {
			lastErr = fmt.Errorf("fetch payload: %w", err)
			continue
		}
		if err := verifySignature(v.PublicKey, body.Bytes(), sig); err != nil {
			lastErr = err
			continue
		}
		if err := checkPayload(body.Bytes(), target); err != nil {
			lastErr = err
			continue
		}
		return nil // success on first usable layer
	}
	if lastErr != nil {
		return fmt.Errorf("cosign: %w", lastErr)
	}
	return errors.New("cosign: no simplesigning layer in signature manifest")
}

func verifySignature(pub crypto.PublicKey, payload, sig []byte) error {
	h := sha256.Sum256(payload)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, h[:], sig) {
			return errors.New("ECDSA verify failed")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
	case ed25519.PublicKey:
		// Ed25519 signs the message directly, not its hash.
		if !ed25519.Verify(k, payload, sig) {
			return errors.New("Ed25519 verify failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key type %T", pub)
}

type payloadEnvelope struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Type string `json:"type"`
	} `json:"critical"`
}

func checkPayload(body []byte, want digest.Digest) error {
	var env payloadEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Critical.Image.DockerManifestDigest != want.String() {
		return fmt.Errorf("digest mismatch: payload=%s, manifest=%s",
			env.Critical.Image.DockerManifestDigest, want)
	}
	return nil
}
