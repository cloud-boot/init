package cosign

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/cloud-boot/init/pkg/oci"
)

// generateX25519PEM produces a PEM-encoded PKIX SubjectPublicKeyInfo block
// holding an X25519 public key. Go's x509.ParsePKIXPublicKey returns
// *ecdh.PublicKey for this curve — a type our verifier explicitly does not
// support, which lets us exercise the unsupported-key-type error branch.
func generateX25519PEM() ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func pemEncode(t *testing.T, pub interface{}) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func signECDSA(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func signRSA(t *testing.T, key *rsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func signEd25519(t *testing.T, key ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	return ed25519.Sign(key, payload)
}

// fixture sets up a registry that serves the target manifest, the legacy
// signature manifest at "<algo>-<hex>.sig", and the simplesigning payload.
type fixture struct {
	server   *httptest.Server
	target   []byte
	tDigest  digest.Digest
	envelope []byte
	sig      []byte
}

func buildEnvelope(t *testing.T, target digest.Digest) []byte {
	t.Helper()
	env := payloadEnvelope{}
	env.Critical.Image.DockerManifestDigest = target.String()
	env.Critical.Identity.DockerReference = "x"
	env.Critical.Type = "cosign container image signature"
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func startFixture(t *testing.T, sign func(payload []byte) []byte) *fixture {
	t.Helper()
	f := &fixture{}
	f.target = []byte(`{"target":"manifest"}`)
	f.tDigest = digest.FromBytes(f.target)
	f.envelope = buildEnvelope(t, f.tDigest)
	f.sig = sign(f.envelope)
	sigManifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{
			{
				MediaType: mediaTypeSimpleSigning,
				Digest:    digest.FromBytes(f.envelope),
				Size:      int64(len(f.envelope)),
				Annotations: map[string]string{
					annotationSignature: base64.StdEncoding.EncodeToString(f.sig),
				},
			},
		},
	}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	sigTag := fmt.Sprintf("%s-%s.sig", f.tDigest.Algorithm(), f.tDigest.Encoded())

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write(f.target)
	})
	mux.HandleFunc("/v2/r/manifests/"+sigTag, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write(sigRaw)
	})
	mux.HandleFunc("/v2/r/blobs/"+digest.FromBytes(f.envelope).String(), func(w http.ResponseWriter, r *http.Request) {
		w.Write(f.envelope)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func withSingleEndpoint(t *testing.T, host string) {
	t.Helper()
	prev := oci.ResolveEndpoints
	_ = prev
	// internal package's resolveEndpoints is unexported; instead point ref.Host at host.
}

func TestParsePublicKey_ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ParsePublicKey(pemEncode(t, &priv.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestParsePublicKey_RSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ParsePublicKey(pemEncode(t, &priv.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestParsePublicKey_Ed25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParsePublicKey(pemEncode(t, pub)); err != nil {
		t.Fatal(err)
	}
}

func TestParsePublicKey_NonPEM(t *testing.T) {
	if _, err := ParsePublicKey([]byte("not pem")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePublicKey_BadPKIX(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")})
	if _, err := ParsePublicKey(bad); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePublicKey_UnsupportedAlgo(t *testing.T) {
	// Go ≥1.20's x509.ParsePKIXPublicKey returns *ecdh.PublicKey for X25519
	// keys. Our verifier only knows ECDSA / RSA / Ed25519, so an X25519
	// key exercises the default "unsupported key type" branch.
	priv, err := generateX25519PEM()
	if err != nil {
		t.Skip("X25519 unsupported on this runtime: ", err)
	}
	if _, err := ParsePublicKey(priv); err == nil {
		t.Fatal("expected unsupported-key-type error")
	}
}

func TestVerifier_NilNoOp(t *testing.T) {
	var v *Verifier
	if err := v.Verify(oci.NewClient(), &oci.Ref{}); err != nil {
		t.Errorf("nil verifier should no-op, got %v", err)
	}
}

func TestVerify_ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := startFixture(t, func(p []byte) []byte { return signECDSA(t, priv, p) })
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	c := oci.NewClient()
	u, _ := url.Parse(f.server.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(c, ref); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_RSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := startFixture(t, func(p []byte) []byte { return signRSA(t, priv, p) })
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	c := oci.NewClient()
	u, _ := url.Parse(f.server.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(c, ref); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := startFixture(t, func(p []byte) []byte { return signEd25519(t, priv, p) })
	v, _ := ParsePublicKey(pemEncode(t, pub))
	c := oci.NewClient()
	u, _ := url.Parse(f.server.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(c, ref); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_TargetManifestError(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected target manifest fetch error")
	}
}

func TestVerify_SignatureManifestError(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected signature manifest fetch error")
	}
}

func TestVerify_NoSimpleSigningLayer(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	sig := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{
			{MediaType: "application/other", Digest: digest.FromBytes([]byte("x")), Size: 1},
		}}
	sig.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sig)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) {
		w.Write(target)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected no-simplesigning-layer error")
	}
}

func TestVerify_MissingSignatureAnnotation(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	envelope := buildEnvelope(t, tDigest)
	sigManifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{{
			MediaType: mediaTypeSimpleSigning,
			Digest:    digest.FromBytes(envelope),
			Size:      int64(len(envelope)),
		}}}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) { w.Write(target) })
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected missing-annotation error")
	}
}

func TestVerify_BadBase64Signature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	envelope := buildEnvelope(t, tDigest)
	sigManifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{{
			MediaType:   mediaTypeSimpleSigning,
			Digest:      digest.FromBytes(envelope),
			Size:        int64(len(envelope)),
			Annotations: map[string]string{annotationSignature: "!!!not base64!!!"},
		}}}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) { w.Write(target) })
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected base64 decode error")
	}
}

func TestVerify_PayloadFetchError(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	envelope := buildEnvelope(t, tDigest)
	sig := signECDSA(t, priv, envelope)
	sigManifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{{
			MediaType:   mediaTypeSimpleSigning,
			Digest:      digest.FromBytes(envelope),
			Size:        int64(len(envelope)),
			Annotations: map[string]string{annotationSignature: base64.StdEncoding.EncodeToString(sig)},
		}}}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) { w.Write(target) })
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	// /v2/r/blobs/... intentionally not registered → 404 → fetch error.
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected payload fetch error")
	}
}

func TestVerify_BadSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Sign with `priv` but verify with `other`'s public key.
	f := startFixture(t, func(p []byte) []byte { return signECDSA(t, priv, p) })
	v, _ := ParsePublicKey(pemEncode(t, &other.PublicKey))
	c := oci.NewClient()
	u, _ := url.Parse(f.server.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(c, ref); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestVerify_DigestMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	// Envelope claims a different digest.
	wrong := payloadEnvelope{}
	wrong.Critical.Image.DockerManifestDigest = "sha256:" + strings.Repeat("0", 64)
	wrong.Critical.Type = "x"
	envelope, _ := json.Marshal(wrong)
	sig := signECDSA(t, priv, envelope)
	sigManifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{{
			MediaType:   mediaTypeSimpleSigning,
			Digest:      digest.FromBytes(envelope),
			Size:        int64(len(envelope)),
			Annotations: map[string]string{annotationSignature: base64.StdEncoding.EncodeToString(sig)},
		}}}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) { w.Write(target) })
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	mux.HandleFunc("/v2/r/blobs/"+digest.FromBytes(envelope).String(), func(w http.ResponseWriter, r *http.Request) {
		w.Write(envelope)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

func TestVerify_BadEnvelopeJSON(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, _ := ParsePublicKey(pemEncode(t, &priv.PublicKey))
	target := []byte(`{}`)
	tDigest := digest.FromBytes(target)
	envelope := []byte("{not json")
	sig := signECDSA(t, priv, envelope)
	sigManifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{{
			MediaType:   mediaTypeSimpleSigning,
			Digest:      digest.FromBytes(envelope),
			Size:        int64(len(envelope)),
			Annotations: map[string]string{annotationSignature: base64.StdEncoding.EncodeToString(sig)},
		}}}
	sigManifest.SchemaVersion = 2
	sigRaw, _ := json.Marshal(sigManifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/manifests/tag", func(w http.ResponseWriter, r *http.Request) { w.Write(target) })
	mux.HandleFunc(fmt.Sprintf("/v2/r/manifests/%s-%s.sig", tDigest.Algorithm(), tDigest.Encoded()),
		func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	mux.HandleFunc("/v2/r/blobs/"+digest.FromBytes(envelope).String(), func(w http.ResponseWriter, r *http.Request) {
		w.Write(envelope)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ref := &oci.Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if err := v.Verify(oci.NewClient(), ref); err == nil {
		t.Fatal("expected envelope decode error")
	}
}

func TestVerifySignature_UnsupportedKey(t *testing.T) {
	type strange struct{}
	if err := verifySignature(strange{}, []byte("x"), []byte("y")); err == nil {
		t.Fatal("expected unsupported-key error")
	}
}

func TestVerifySignature_ECDSAFail(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifySignature(&priv.PublicKey, []byte("x"), []byte("garbage")); err == nil {
		t.Fatal("expected ecdsa failure")
	}
}

func TestVerifySignature_RSAFail(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := verifySignature(&priv.PublicKey, []byte("x"), []byte("garbage")); err == nil {
		t.Fatal("expected rsa failure")
	}
}

func TestVerifySignature_Ed25519Fail(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifySignature(pub, []byte("x"), []byte("garbage")); err == nil {
		t.Fatal("expected ed25519 failure")
	}
}

func TestCheckPayload_BadJSON(t *testing.T) {
	if err := checkPayload([]byte("not json"), "sha256:abc"); err == nil {
		t.Fatal("expected json decode error")
	}
}

// Sanity that errors module is referenced (silences unused-import linters
// if some future refactor removes the only `errors.` usage).
var _ = errors.New
