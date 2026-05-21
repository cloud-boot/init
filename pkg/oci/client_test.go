package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// withSingleEndpoint pins resolveEndpoints to a single host for the duration
// of the test, undoing any earlier override on cleanup.
func withSingleEndpoint(t *testing.T, host string) {
	t.Helper()
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) { return []Endpoint{{Host: host}}, nil }
	t.Cleanup(func() { resolveEndpoints = prev })
}

func newRefForServer(t *testing.T, srv *httptest.Server, repo, ref string) *Ref {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	withSingleEndpoint(t, u.Host)
	return &Ref{Scheme: u.Scheme, Host: u.Host, Repo: repo, Reference: ref}
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in, scheme, host, repo, ref string
	}{
		{"registry.example.com/repo:tag", "https", "registry.example.com", "repo", "tag"},
		{"https://registry.example.com/repo:tag", "https", "registry.example.com", "repo", "tag"},
		{"http://registry.example.com/repo:tag", "http", "registry.example.com", "repo", "tag"},
		{"127.0.0.1:5000/r:t", "http", "127.0.0.1:5000", "r", "t"},
		{"localhost:5000/r:t", "http", "localhost:5000", "r", "t"},
		{"r.example.com/p/r@sha256:abc", "https", "r.example.com", "p/r", "sha256:abc"},
		{"r.example.com/r", "https", "r.example.com", "r", "latest"},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if r.Scheme != c.scheme || r.Host != c.host || r.Repo != c.repo || r.Reference != c.ref {
			t.Errorf("%s -> %+v want {%s,%s,%s,%s}", c.in, r, c.scheme, c.host, c.repo, c.ref)
		}
	}
}

func TestParseRef_MissingRepo(t *testing.T) {
	if _, err := ParseRef("noslash"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRef_LocalhostAlwaysHttp(t *testing.T) {
	// Documented quirk: refs targeting localhost / 127.0.0.1 default to plain
	// HTTP even when the user typed `https://`. Operators who really want
	// HTTPS to localhost can use a different host (e.g. host.docker.internal).
	r, err := ParseRef("https://localhost:5000/r:t")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "http" {
		t.Errorf("scheme = %s; expected localhost http override", r.Scheme)
	}
}

func TestBase(t *testing.T) {
	r := &Ref{Scheme: "http", Host: "h:1", Repo: "r"}
	if got := r.base(); got != "http://h:1/v2/r" {
		t.Errorf("base = %s", got)
	}
}

func TestSplitChallenge(t *testing.T) {
	in := `realm="https://auth/token",service="reg",scope="repository:r:pull"`
	got := splitChallenge(in)
	if len(got) != 3 {
		t.Fatalf("len = %d", len(got))
	}
	if got[2] != `scope="repository:r:pull"` {
		t.Errorf("got[2] = %q", got[2])
	}
}

func TestSplitChallenge_TrailingComma(t *testing.T) {
	if got := splitChallenge(`a="b",c="d"`); len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestSplitChallenge_Empty(t *testing.T) {
	if got := splitChallenge(""); len(got) != 0 {
		t.Errorf("expected zero parts, got %v", got)
	}
}

func TestShouldRetryStatus(t *testing.T) {
	for _, s := range []int{200, 201, 401, 404} {
		if shouldRetryStatus(s) {
			t.Errorf("%d should not retry", s)
		}
	}
	for _, s := range []int{408, 429, 500, 502, 503, 504} {
		if !shouldRetryStatus(s) {
			t.Errorf("%d should retry", s)
		}
	}
}

func TestIsRetriableNetErr(t *testing.T) {
	if isRetriableNetErr(nil) {
		t.Error("nil err should not be retriable")
	}
	if !isRetriableNetErr(fmt.Errorf("boom")) {
		t.Error("non-nil err should be retriable")
	}
}

func TestIsIndex(t *testing.T) {
	if !isIndex(nil, ocispec.MediaTypeImageIndex) {
		t.Error("by content-type should detect")
	}
	if !isIndex([]byte(`{"manifests":[{}]}`), "") {
		t.Error("by manifests presence should detect")
	}
	if isIndex([]byte(`{"mediaType":"x"}`), "") {
		t.Error("simple manifest should not be reported as index")
	}
	if isIndex([]byte("not json"), "") {
		t.Error("invalid json should not be reported as index")
	}
}

// fixture serves a minimal repo with config blob, layer blob, and manifest.
type fixture struct {
	server     *httptest.Server
	manifest   []byte
	mDigest    digest.Digest
	layer      []byte
	lDigest    digest.Digest
	indexRaw   []byte
	indexDig   digest.Digest
	want401For map[string]bool // url path → require Bearer
}

func newFixture(t *testing.T, want401 bool) *fixture {
	t.Helper()
	f := &fixture{want401For: map[string]bool{}}

	f.layer = []byte("hello-layer")
	f.lDigest = digest.FromBytes(f.layer)
	cfg := []byte(`{}`)
	cDigest := digest.FromBytes(cfg)
	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.Descriptor{MediaType: "application/json", Digest: cDigest, Size: int64(len(cfg))},
		Layers: []ocispec.Descriptor{
			{MediaType: MediaTypeKernel, Digest: f.lDigest, Size: int64(len(f.layer))},
		},
	}
	manifest.SchemaVersion = 2
	f.manifest, _ = json.Marshal(manifest)
	f.mDigest = digest.FromBytes(f.manifest)

	// Build a multi-arch index that points at the manifest digest twice
	// (linux/amd64 and linux/arm64) plus an entry with no platform.
	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: f.mDigest, Size: int64(len(f.manifest)),
				Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
			{MediaType: ocispec.MediaTypeImageManifest, Digest: f.mDigest, Size: int64(len(f.manifest)),
				Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64"}},
			{MediaType: ocispec.MediaTypeImageManifest, Digest: f.mDigest, Size: int64(len(f.manifest))},
		},
	}
	idx.SchemaVersion = 2
	f.indexRaw, _ = json.Marshal(idx)
	f.indexDig = digest.FromBytes(f.indexRaw)

	authIssued := false

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Bearer-required path.
		if want401 && !authIssued && r.URL.Path != "/token" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+f.server.URL+`/token",service="reg",scope="repository:r:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/token":
			authIssued = true
			w.WriteHeader(200)
			fmt.Fprint(w, `{"token":"tok"}`)
			return
		case strings.HasPrefix(r.URL.Path, "/v2/r/manifests/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v2/r/manifests/")
			switch r.Method {
			case "GET":
				switch ref {
				case "tag", f.mDigest.String():
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Write(f.manifest)
				case "idx":
					w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
					w.Write(f.indexRaw)
				case "missarch":
					// Index missing the runtime arch.
					empty := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex,
						Manifests: []ocispec.Descriptor{{
							MediaType: ocispec.MediaTypeImageManifest, Digest: f.mDigest,
							Platform: &ocispec.Platform{OS: "darwin", Architecture: "ppc64"},
						}}}
					empty.SchemaVersion = 2
					b, _ := json.Marshal(empty)
					w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
					w.Write(b)
				case "badjson":
					w.Write([]byte("{not json"))
				case "indexbadinner":
					inner := []byte("not json either")
					innerDig := digest.FromBytes(inner)
					idx2 := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex,
						Manifests: []ocispec.Descriptor{{
							MediaType: ocispec.MediaTypeImageManifest, Digest: innerDig,
							Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"},
						}}}
					idx2.SchemaVersion = 2
					b, _ := json.Marshal(idx2)
					w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
					w.Write(b)
				default:
					http.NotFound(w, r)
				}
			case "PUT":
				// Echo Created for push tests.
				w.WriteHeader(201)
			case "HEAD":
				w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
				w.WriteHeader(200)
			}
		case strings.HasPrefix(r.URL.Path, "/v2/r/blobs/uploads/"):
			// Initial POST → return Location.
			loc := f.server.URL + "/upload/abc"
			w.Header().Set("Location", loc)
			w.WriteHeader(202)
		case strings.HasPrefix(r.URL.Path, "/upload/"):
			// PUT completes the upload.
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(201)
		case strings.HasPrefix(r.URL.Path, "/v2/r/blobs/"):
			d := strings.TrimPrefix(r.URL.Path, "/v2/r/blobs/")
			switch r.Method {
			case "HEAD":
				if d == f.lDigest.String() {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(404)
				}
			case "GET":
				if d == f.lDigest.String() {
					w.Write(f.layer)
					return
				}
				if d == "sha256:dead" {
					w.Write([]byte("wrong"))
					return
				}
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func TestPullManifest_OK(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	m, raw, err := c.PullManifest(ref)
	if err != nil {
		t.Fatal(err)
	}
	if m.Config.Digest == "" || len(raw) == 0 {
		t.Errorf("manifest empty: %+v", m)
	}
}

func TestPullManifest_BadJSON(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "badjson")
	if _, _, err := c.PullManifest(ref); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestPullManifest_NonOKStatus(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "nope")
	if _, _, err := c.PullManifest(ref); err == nil {
		t.Fatal("expected non-OK error")
	}
}

func TestPullManifestForPlatform_Flat(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	m, _, err := c.PullManifestForPlatform(ref, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if m.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("mediaType = %s", m.MediaType)
	}
}

func TestPullManifestForPlatform_Index(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "idx")
	m, _, err := c.PullManifestForPlatform(ref, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if m.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("mediaType = %s", m.MediaType)
	}
}

func TestPullManifestForPlatform_IndexMiss(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "missarch")
	if _, _, err := c.PullManifestForPlatform(ref, "linux", "amd64"); err == nil {
		t.Fatal("expected no-arch-in-index error")
	}
}

func TestPullManifestForPlatform_BadInner(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "indexbadinner")
	if _, _, err := c.PullManifestForPlatform(ref, "linux", "amd64"); err == nil {
		t.Fatal("expected inner-fetch error")
	}
}

func TestPullManifestForPlatform_BadIndexJSON(t *testing.T) {
	// Hand-roll a response that says content-type is index but body is junk.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "x"}
	if _, _, err := NewClient().PullManifestForPlatform(ref, "linux", "amd64"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestPullManifestForPlatform_BadManifestJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "x"}
	if _, _, err := NewClient().PullManifestForPlatform(ref, "linux", "amd64"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDescribeManifest(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	d, err := c.DescribeManifest(ref)
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest != f.mDigest {
		t.Errorf("digest = %s", d.Digest)
	}
}

func TestDescribeManifest_NoContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't set Content-Type; client must peek inside.
		w.Header().Set("Content-Type", "")
		m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
		m.SchemaVersion = 2
		body, _ := json.Marshal(m)
		w.Write(body)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "x"}
	d, err := NewClient().DescribeManifest(ref)
	if err != nil {
		t.Fatal(err)
	}
	if d.MediaType == "" {
		t.Error("expected DescribeManifest to fill mediaType")
	}
}

func TestDescribeManifest_NoMediaTypeAtAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force empty Content-Type AND empty mediaType in body so the inner
		// fallback to MediaTypeImageManifest fires.
		w.Header()["Content-Type"] = nil
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "x"}
	d, err := NewClient().DescribeManifest(ref)
	if err != nil {
		t.Fatal(err)
	}
	if d.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("default mediaType = %s", d.MediaType)
	}
}

func TestDescribeManifest_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "x"}
	if _, err := NewClient().DescribeManifest(ref); err == nil {
		t.Fatal("expected error")
	}
}

func TestPullBlob(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	var buf bytes.Buffer
	n, err := c.PullBlob(ref, f.lDigest, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(f.layer)) || !bytes.Equal(buf.Bytes(), f.layer) {
		t.Errorf("blob mismatch: %d bytes, %q", n, buf.String())
	}
}

func TestPullBlob_DigestMismatch(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	if _, err := c.PullBlob(ref, digest.Digest("sha256:dead"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected digest mismatch")
	}
}

func TestPullBlob_NotFound(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	if _, err := c.PullBlob(ref, digest.Digest("sha256:0000"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected 404")
	}
}

// failingWriter always errors on Write — used to exercise PullBlob's
// io.Copy error branch.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("boom") }

func TestPullBlob_WriterError(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	if _, err := c.PullBlob(ref, f.lDigest, failingWriter{}); err == nil {
		t.Fatal("expected copy error")
	}
}

func TestPushBlob_Monolithic(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	data := []byte("payload")
	d, err := c.PushBlob(ref, data)
	if err != nil {
		t.Fatal(err)
	}
	if d != digest.FromBytes(data) {
		t.Errorf("digest mismatch: %s", d)
	}
}

func TestPushBlob_HeadExists(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	// f.layer is exactly the bytes the HEAD check at /v2/r/blobs/<lDigest>
	// reports as already-present (200), so PushBlob should return early.
	if _, err := c.PushBlob(ref, f.layer); err != nil {
		t.Fatal(err)
	}
}

func TestPushManifest(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	m := &ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	if _, err := c.PushManifest(ref, m); err != nil {
		t.Fatal(err)
	}
}

func TestPushIndex(t *testing.T) {
	f := newFixture(t, false)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	idx := &ocispec.Index{MediaType: ocispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	if _, err := c.PushIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
}

func TestPutManifest_StatusFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // not 201
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	m := &ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	if _, err := NewClient().PushManifest(ref, m); err == nil {
		t.Fatal("expected non-201")
	}
}

func TestPushBlob_UploadInitFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/r/blobs/") && r.Method == "HEAD" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected init-upload error")
	}
}

func TestPushBlob_NoLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(202) // accepted but no Location
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected missing-location error")
	}
}

func TestPushBlob_RelativeLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/r/blobs/uploads/") {
			w.Header().Set("Location", "/up/abc?x=1") // relative
			w.WriteHeader(202)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/up/") {
			w.WriteHeader(201)
			return
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestPushBlob_InvalidLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Location", "::not-a-url")
		w.WriteHeader(202)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected url.Parse error")
	}
}

func TestPushBlob_PutFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/r/blobs/uploads/") {
			w.Header().Set("Location", "/up/abc")
			w.WriteHeader(202)
			return
		}
		w.WriteHeader(400) // PUT fails
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected PUT error")
	}
}

// Test 401 → Bearer flow.
func TestDo_BearerAuthFlow(t *testing.T) {
	f := newFixture(t, true)
	c := NewClient()
	ref := newRefForServer(t, f.server, "r", "tag")
	if _, _, err := c.PullManifest(ref); err != nil {
		t.Fatal(err)
	}
}

func TestDo_401NoChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err == nil {
		t.Fatal("expected no-challenge error")
	}
}

func TestDo_BasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "alice" || p != "s3kret" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write([]byte(`{"mediaType":"` + ocispec.MediaTypeImageManifest + `"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	c := NewClient()
	c.Username, c.Password = "alice", "s3kret"
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := c.PullManifest(ref); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAuth_NoTokenNoCreds(t *testing.T) {
	c := NewClient()
	c.Username, c.Password = "", ""
	req, _ := http.NewRequest("GET", "http://x/", nil)
	c.applyAuth(&Ref{Host: "x"}, req)
	if req.Header.Get("Authorization") != "" {
		t.Error("did not expect Authorization header")
	}
}

// Token retrieval helpers.
func TestFetchBearer_UnsupportedScheme(t *testing.T) {
	c := NewClient()
	if _, err := c.fetchBearer("Digest realm=x"); err == nil {
		t.Fatal("expected unsupported error")
	}
}

func TestFetchBearer_MissingRealm(t *testing.T) {
	c := NewClient()
	if _, err := c.fetchBearer(`Bearer service="x"`); err == nil {
		t.Fatal("expected missing-realm error")
	}
}

func TestFetchBearer_InvalidRealm(t *testing.T) {
	c := NewClient()
	if _, err := c.fetchBearer(`Bearer realm=::bad`); err == nil {
		t.Fatal("expected url-parse error")
	}
}

func TestFetchBearer_HTTPNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()
	c := NewClient()
	if _, err := c.fetchBearer(`Bearer realm="` + srv.URL + `"`); err == nil {
		t.Fatal("expected non-200 error")
	}
}

func TestFetchBearer_AccessTokenFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"alt"}`)
	}))
	defer srv.Close()
	c := NewClient()
	tok, err := c.fetchBearer(`Bearer realm="` + srv.URL + `"`)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "alt" {
		t.Errorf("token = %q", tok)
	}
}

func TestFetchBearer_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	c := NewClient()
	if _, err := c.fetchBearer(`Bearer realm="` + srv.URL + `"`); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFetchBearer_WithBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"token":"t"}`)
	}))
	defer srv.Close()
	c := NewClient()
	c.Username, c.Password = "u", "p"
	if _, err := c.fetchBearer(`Bearer realm="` + srv.URL + `"`); err != nil {
		t.Fatal(err)
	}
}

func TestFetchBearer_SkipMalformedParam(t *testing.T) {
	// `Bearer realm="x"=y,service="ok"` — first param has 3 '=' parts after split.
	// We want the parser to skip the malformed one and not crash.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"t"}`)
	}))
	defer srv.Close()
	c := NewClient()
	chal := `Bearer realm="` + srv.URL + `",malformedparam,service="x"`
	if _, err := c.fetchBearer(chal); err != nil {
		t.Fatal(err)
	}
}

func TestDo_ConnectionError(t *testing.T) {
	// Two endpoints, both pointing at a closed server → all-endpoints-failed
	// path through do(). Spin up a server, get URL, close, then try.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()
	u, _ := url.Parse(closedURL)
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		return []Endpoint{{Host: u.Host}, {Host: u.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err == nil {
		t.Fatal("expected connection error")
	}
}

func TestDo_FifthhundredFailoverThenOK(t *testing.T) {
	// First endpoint returns 503; second returns 200.
	good := newFixture(t, false)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer bad.Close()

	gu, _ := url.Parse(good.server.URL)
	bu, _ := url.Parse(bad.URL)
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		return []Endpoint{{Host: bu.Host}, {Host: gu.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })

	ref := &Ref{Scheme: gu.Scheme, Host: gu.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err != nil {
		t.Fatal(err)
	}
}

func TestDo_ResolveError(t *testing.T) {
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) { return nil, fmt.Errorf("nope") }
	t.Cleanup(func() { resolveEndpoints = prev })
	ref := &Ref{Scheme: "http", Host: "x", Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err == nil {
		t.Fatal("expected resolve error")
	}
}

// failingReader returns an error after delivering some initial bytes; used to
// fail the read inside the upload path.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, fmt.Errorf("read boom") }

// failingGetBody constructs a Request whose GetBody returns an error,
// exercising rewriteHost's rewind-error branch and doOnce's auth-retry
// rewind-error branch without crossing the public Push/Pull API.
func failingGetBody() *http.Request {
	r, _ := http.NewRequest("GET", "http://placeholder/x", bytes.NewReader([]byte("body")))
	r.GetBody = func() (io.ReadCloser, error) { return nil, fmt.Errorf("rewind boom") }
	return r
}

func TestRewriteHost_BodyRewindError(t *testing.T) {
	req := failingGetBody()
	if err := rewriteHost(req, "newhost"); err == nil {
		t.Fatal("expected rewind error")
	}
}

func TestDoOnce_BodyRewindOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tok" {
			fmt.Fprint(w, `{"token":"t"}`)
			return
		}
		w.Header().Set("Www-Authenticate", `Bearer realm="http://`+r.Host+`/tok"`)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r, _ := http.NewRequest("GET", srv.URL+"/x", bytes.NewReader([]byte("body")))
	r.GetBody = func() (io.ReadCloser, error) { return nil, fmt.Errorf("rewind boom") }

	c := NewClient()
	if _, err := c.doOnce(&Ref{Host: u.Host}, r); err == nil {
		t.Fatal("expected GetBody-rewind error")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestHeadBlob_NetError(t *testing.T) {
	// Closed server → headBlob's c.do returns an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()
	u, _ := url.Parse(closedURL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().headBlob(ref, digest.Digest("sha256:abc")); err == nil {
		t.Fatal("expected do error")
	}
}

func TestPullBlob_NetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()
	u, _ := url.Parse(closedURL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, err := NewClient().PullBlob(ref, digest.Digest("sha256:abc"), io.Discard); err == nil {
		t.Fatal("expected do error")
	}
}

func TestPutManifest_NetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()
	u, _ := url.Parse(closedURL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	m := &ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	if _, err := NewClient().PushManifest(ref, m); err == nil {
		t.Fatal("expected do error")
	}
}

func TestIsIndex_ByJSONMediaType(t *testing.T) {
	// content-type empty, but the JSON body declares the index mediaType.
	body := []byte(`{"mediaType":"` + ocispec.MediaTypeImageIndex + `"}`)
	if !isIndex(body, "") {
		t.Error("by JSON mediaType should detect")
	}
	body2 := []byte(`{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}`)
	if !isIndex(body2, "") {
		t.Error("docker manifest list (in JSON) should be detected")
	}
}

func TestIsIndex_DockerListContentType(t *testing.T) {
	if !isIndex(nil, "application/vnd.docker.distribution.manifest.list.v2+json") {
		t.Error("by docker-list content-type should detect")
	}
}

func TestPullManifestForPlatform_SkipsNoPlatformEntries(t *testing.T) {
	mux := http.NewServeMux()
	manifest := []byte(`{"mediaType":"` + ocispec.MediaTypeImageManifest + `","schemaVersion":2}`)
	mDigest := digest.FromBytes(manifest)
	// First descriptor has no Platform → exercise the `continue` branch.
	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: mDigest, Size: int64(len(manifest))},
			{MediaType: ocispec.MediaTypeImageManifest, Digest: mDigest, Size: int64(len(manifest)),
				Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
		},
	}
	idx.SchemaVersion = 2
	idxRaw, _ := json.Marshal(idx)
	mux.HandleFunc("/v2/r/manifests/idx", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Write(idxRaw)
	})
	mux.HandleFunc("/v2/r/manifests/"+mDigest.String(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Write(manifest)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "idx"}
	if _, _, err := NewClient().PullManifestForPlatform(ref, "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
}

func TestDo_AllEndpoints5xx(t *testing.T) {
	// Every endpoint returns 503 → do() exhausts the list and returns the
	// last error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		return []Endpoint{{Host: u.Host}, {Host: u.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err == nil {
		t.Fatal("expected 5xx error after exhausting endpoints")
	}
}

func TestRewriteHost_NoGetBody(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://h/x", nil)
	if err := rewriteHost(r, "other"); err != nil {
		t.Fatal(err)
	}
	if r.URL.Host != "other" || r.Host != "other" {
		t.Errorf("rewriteHost did not swap: %+v", r.URL)
	}
}

// silence unused import warning if all references later disappear
var _ = failingReader{}

func TestPullManifestForPlatform_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()
	u, _ := url.Parse(closedURL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifestForPlatform(ref, "linux", "amd64"); err == nil {
		t.Fatal("expected fetch error")
	}
}

func TestPushBlob_POSTNetError(t *testing.T) {
	// HEAD answers 404 immediately (no body), then we close the server so the
	// subsequent POST fails with a network error.
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(404)
	}))
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	t.Cleanup(srv.Close)
	// Hijack a connection to make further requests fail: easier to just close
	// the server after the HEAD round-trip. We do it via a custom transport.
	// Alternative: just point to a port no one listens on.
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closed := closedSrv.URL
	closedSrv.Close()
	u2, _ := url.Parse(closed)
	prev := resolveEndpoints
	resolveEndpoints = func(host string) ([]Endpoint, error) {
		// HEAD uses srv (returns 404); subsequent POST uses closedSrv via
		// different ref handling? Simpler: just point everything at u2 — HEAD
		// will also fail, falling through to POST which also fails.
		return []Endpoint{{Host: u2.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })
	ref := &Ref{Scheme: u2.Scheme, Host: u2.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected POST error")
	}
	_ = count
}

func TestPushBlob_PUTNetError(t *testing.T) {
	// Custom server that 404s HEAD, returns 202 with a Location, then the
	// listener is hijacked-closed so the PUT cannot complete.
	var listener net.Listener
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "HEAD":
			w.WriteHeader(404)
		case strings.HasPrefix(r.URL.Path, "/v2/r/blobs/uploads/"):
			// Point PUT at an unreachable host.
			w.Header().Set("Location", "http://127.0.0.1:1/upload/abc")
			w.WriteHeader(202)
		default:
			w.WriteHeader(500)
		}
	}))
	srv.Listener = mustListen(t)
	listener = srv.Listener
	_ = listener
	srv.Start()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("x")); err == nil {
		t.Fatal("expected PUT error")
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestPushBlob_PUTOnlyNetError(t *testing.T) {
	// HEAD 404, POST 202 with a same-host Location; then a stateful resolver
	// flips to a closed host so only the PUT round-trip fails.
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/r/blobs/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	mux.HandleFunc("/v2/r/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/upload/abc")
		w.WriteHeader(202)
	})
	live := httptest.NewServer(mux)
	defer live.Close()
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()
	lu, _ := url.Parse(live.URL)
	cu, _ := url.Parse(closedURL)

	calls := 0
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		calls++
		// HEAD (1) and POST init (2) hit the live server; PUT (3) is sent to
		// the closed host so c.do returns a network error.
		if calls <= 2 {
			return []Endpoint{{Host: lu.Host}}, nil
		}
		return []Endpoint{{Host: cu.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })

	ref := &Ref{Scheme: lu.Scheme, Host: lu.Host, Repo: "r"}
	if _, err := NewClient().PushBlob(ref, []byte("payload")); err == nil {
		t.Fatal("expected PUT c.do error")
	}
}

func TestDoOnce_FetchBearerError(t *testing.T) {
	// Server returns 401 with a Bearer challenge whose realm cannot be parsed,
	// forcing fetchBearer to error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Bearer realm="::bad"`)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := NewClient().PullManifest(ref); err == nil {
		t.Fatal("expected fetchBearer error")
	}
}

func TestDoOnce_BearerOnPUT(t *testing.T) {
	// Exercises the doOnce body-rewind happy path: 401 → fetchBearer succeeds
	// → GetBody returns a fresh reader → r2.Body assignment is reached.
	authIssued := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tok" {
			fmt.Fprint(w, `{"token":"t"}`)
			return
		}
		if !authIssued {
			authIssued = true
			w.Header().Set("Www-Authenticate", `Bearer realm="http://`+r.Host+`/tok"`)
			w.WriteHeader(401)
			return
		}
		// Confirm the bearer is being presented on the retry.
		if a := r.Header.Get("Authorization"); a != "Bearer t" {
			w.WriteHeader(500)
			return
		}
		// PushManifest expects 201.
		w.WriteHeader(201)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)
	c := NewClient()
	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	m := &ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	if _, err := c.PushManifest(ref, m); err != nil {
		t.Fatal(err)
	}
}

func TestFetchBearer_NetError(t *testing.T) {
	// realm points at a closed port → c.HTTP.Do returns a network error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closed := srv.URL
	srv.Close()
	c := NewClient()
	if _, err := c.fetchBearer(`Bearer realm="` + closed + `"`); err == nil {
		t.Fatal("expected HTTP.Do error")
	}
}

func TestDo_RewriteHostError(t *testing.T) {
	// Multi-endpoint resolver; rewriteHost fails on the very first iteration
	// because the request's GetBody is wired to fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		return []Endpoint{{Host: u.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })
	req, _ := http.NewRequest("PUT", "http://placeholder/v2/r/manifests/tag",
		bytes.NewReader([]byte("body")))
	req.GetBody = func() (io.ReadCloser, error) { return nil, fmt.Errorf("rewind boom") }
	if _, err := NewClient().do(&Ref{Host: u.Host}, req); err == nil {
		t.Fatal("expected rewriteHost error")
	}
}

// TestNewClient_H2C verifies that NewClient builds an HTTP/2 cleartext
// (h2c) transport when REGISTRY_HTTP2_CLEARTEXT=1, and that the
// resulting client actually negotiates HTTP/2 over a plaintext
// listener that speaks h2 prior knowledge.
func TestNewClient_H2C(t *testing.T) {
	// Stand up a plaintext HTTP/2 server (httptest.Server is HTTP/1
	// only — we need a manual http2.Server tied to net.Listen).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Proto", r.Proto)
		_, _ = io.WriteString(w, "ok")
	})
	// h2c.NewHandler intercepts the connection-preface bytes on the
	// plaintext listener and hands the conn to http2 — which is what
	// our REGISTRY_HTTP2_CLEARTEXT=1 client opens (h2 prior knowledge,
	// no Upgrade dance).
	srv := &http.Server{Handler: h2c.NewHandler(handler, h2s)}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	t.Setenv("REGISTRY_HTTP2_CLEARTEXT", "1")
	c := NewClient()

	addr := "http://" + ln.Addr().String() + "/ping"
	req, _ := http.NewRequest("GET", addr, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("h2c GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("expected HTTP/2.0, got %q", resp.Proto)
	}
	if resp.Header.Get("X-Saw-Proto") != "HTTP/2.0" {
		t.Fatalf("server saw %q, expected HTTP/2.0", resp.Header.Get("X-Saw-Proto"))
	}
}

// TestNewClient_NoH2C verifies the default (no REGISTRY_HTTP2_CLEARTEXT)
// stays on HTTP/1.1 against a plaintext server, so the h2c opt-in
// doesn't quietly alter behaviour for unrelated cloud-boot deployments.
func TestNewClient_NoH2C(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Proto", r.Proto)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	t.Setenv("REGISTRY_HTTP2_CLEARTEXT", "")
	c := NewClient()

	req, _ := http.NewRequest("GET", srv.URL+"/ping", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.HasPrefix(resp.Proto, "HTTP/1") {
		t.Fatalf("expected HTTP/1.x without h2c opt-in, got %q", resp.Proto)
	}
}

func TestPushManifest_FailoverRewindsBody(t *testing.T) {
	// rewriteHost rewinds req.GetBody when retrying at the next endpoint.
	// PushManifest is the cleanest carrier: a single PUT whose body is a
	// bytes.Reader (so GetBody is non-nil and an honest rewind is required).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer bad.Close()
	good := newFixture(t, false)

	gu, _ := url.Parse(good.server.URL)
	bu, _ := url.Parse(bad.URL)
	prev := resolveEndpoints
	resolveEndpoints = func(string) ([]Endpoint, error) {
		return []Endpoint{{Host: bu.Host}, {Host: gu.Host}}, nil
	}
	t.Cleanup(func() { resolveEndpoints = prev })

	ref := &Ref{Scheme: gu.Scheme, Host: gu.Host, Repo: "r", Reference: "tag"}
	m := &ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
	m.SchemaVersion = 2
	if _, err := NewClient().PushManifest(ref, m); err != nil {
		t.Fatal(err)
	}
}

// TestApplyAuth_BearerTokenOverride verifies that a pre-set
// c.BearerToken short-circuits the negotiated-token cache + basic
// auth, sending its value as the Authorization header. Used by the
// Keystone application-credential flow in cloud-boot-init: the
// token minted from {AC id, AC secret} → /v3/auth/tokens becomes
// the registry's Bearer for every request.
func TestApplyAuth_BearerTokenOverride(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		fmt.Fprint(w, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.cncf.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	withSingleEndpoint(t, u.Host)

	c := NewClient()
	c.BearerToken = "keystone-derived-token"
	// Set Username/Password to confirm Bearer wins.
	c.Username, c.Password = "should-not-be-used", "x"

	ref := &Ref{Scheme: u.Scheme, Host: u.Host, Repo: "r", Reference: "tag"}
	if _, _, err := c.PullManifest(ref); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer keystone-derived-token" {
		t.Errorf("Authorization = %q, want Bearer keystone-derived-token", gotAuth)
	}
}
