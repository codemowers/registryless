// Package registry implements the initial OCI image push/pull surface.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/store"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Publisher interface {
	Publish(string, string, ocispec.Descriptor) error
}

type Authenticator interface {
	Check(context.Context, string, string, string, bool) (bool, error)
}
type PushBarrier interface {
	Wait(context.Context, string, string, ocispec.Descriptor) error
}

type Server struct {
	Store         *store.Store
	Keys          auth.Keys
	Publisher     Publisher
	Authenticator Authenticator
	Barrier       PushBarrier
	PushSync      bool
	Authless      bool
	Address       string
	MaxBlob       int64
	Log           *slog.Logger
	Proxy         *http.Client
	// Slots bounds active HTTP requests, including open upload bodies.
	Slots chan struct{}
}

func Namespace(repo string) string { ns, _, _ := strings.Cut(repo, "/"); return ns }

func ValidRepo(repo string) bool {
	if len(repo) > 200 || !strings.Contains(repo, "/") {
		return false
	}
	r, err := reference.WithName(repo)
	return err == nil && r.Name() == repo && !strings.Contains(Namespace(repo), ".")
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": message}}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, repo string, write bool) bool {
	if s.Authless {
		return true
	}
	user, password, ok := r.BasicAuth()
	if s.Authenticator != nil {
		if ok {
			namespace := ""
			if repo != "" {
				namespace = Namespace(repo)
			}
			allowed, err := s.Authenticator.Check(r.Context(), user, password, namespace, write)
			if err != nil {
				s.Log.Warn("registry authentication unavailable", "error", err)
				fail(w, 503, "UNAVAILABLE", "authentication unavailable")
				return false
			}
			if allowed {
				return true
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="registryless"`)
		fail(w, 401, "UNAUTHORIZED", "registry credential or namespace access denied")
		return false
	}
	if ok && (repo == "" || user == Namespace(repo)) {
		roles := []string{"push"}
		if !write {
			roles = append(roles, "pull")
		}
		for _, role := range roles {
			key, err := s.Keys.Key(r.Context(), user, role)
			if err == nil && auth.Equal(key, password) {
				return true
			}
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="registryless"`)
	fail(w, http.StatusUnauthorized, "UNAUTHORIZED", "namespace credential required")
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Slots != nil {
		select {
		case s.Slots <- struct{}{}:
			defer func() { <-s.Slots }()
		default:
			fail(w, 503, "UNAVAILABLE", "request capacity exhausted")
			return
		}
	}
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if strings.HasPrefix(r.URL.Path, "/internal/blobs/") {
		s.internalBlob(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/ready/") {
		s.ready(w, r)
		return
	}
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		if s.authorize(w, r, "", false) {
			w.WriteHeader(200)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v2/") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	var repo, kind, ref string
	for _, candidate := range []string{"/blobs/uploads/", "/manifests/", "/blobs/"} {
		if i := strings.LastIndex(path, candidate); i >= 0 {
			repo, kind, ref = path[:i], candidate, path[i+len(candidate):]
			break
		}
	}
	if !ValidRepo(repo) {
		fail(w, 400, "NAME_INVALID", "repository must be namespace/image")
		return
	}
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if !s.authorize(w, r, repo, write) {
		return
	}
	switch kind {
	case "/blobs/uploads/":
		s.upload(w, r, repo, ref)
	case "/blobs/":
		if !write {
			s.blob(w, r, repo, ref)
		} else {
			fail(w, 405, "UNSUPPORTED", "blob deletion is not supported")
		}
	case "/manifests/":
		s.manifest(w, r, repo, ref)
	default:
		http.NotFound(w, r)
	}
}

func Ticket(key []byte, repo string, dgst digest.Digest, expiry int64) string {
	return auth.MAC(key, "download", []byte(repo+"\n"+dgst.String()+"\n"+strconv.FormatInt(expiry, 10)))
}

func (s *Server) internalBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(405)
		return
	}
	repo := r.URL.Query().Get("repo")
	dgst, err := digest.Parse(strings.TrimPrefix(r.URL.Path, "/internal/blobs/"))
	expiry, parseErr := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	if !ValidRepo(repo) || err != nil || parseErr != nil || expiry < time.Now().Unix() || expiry > time.Now().Add(time.Hour).Unix() {
		w.WriteHeader(403)
		return
	}
	key, err := s.Keys.Key(r.Context(), Namespace(repo), "push")
	if err != nil || !auth.Verify(key, "download", []byte(repo+"\n"+dgst.String()+"\n"+strconv.FormatInt(expiry, 10)), r.URL.Query().Get("signature")) {
		w.WriteHeader(403)
		return
	}
	s.blob(w, r, repo, dgst.String())
}

func (s *Server) blob(w http.ResponseWriter, r *http.Request, repo, ref string) {
	dgst, err := digest.Parse(ref)
	if err != nil {
		fail(w, 400, "DIGEST_INVALID", "invalid digest")
		return
	}
	info, err := s.Store.Info(r.Context(), repo, dgst)
	if err != nil {
		s.readError(w, err)
		return
	}
	ra, err := s.Store.Client.ContentStore().ReaderAt(r.Context(), ocispec.Descriptor{Digest: dgst})
	if err != nil {
		s.readError(w, err)
		return
	}
	defer ra.Close()
	w.Header().Set("Docker-Content-Digest", dgst.String())
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", info.CreatedAt, io.NewSectionReader(ra, 0, ra.Size()))
}

func (s *Server) readError(w http.ResponseWriter, err error) {
	if errdefs.IsNotFound(err) {
		fail(w, 404, "BLOB_UNKNOWN", "content not found")
		return
	}
	s.Log.Error("content read failed", "error", err)
	fail(w, 500, "UNKNOWN", "content store error")
}

func (s *Server) uploadID(repo string, key []byte) string {
	data := base64.RawURLEncoding.EncodeToString([]byte(s.Address)) + "." + randomID()
	return data + "." + auth.MAC(key, "upload", []byte(repo+"\n"+data))
}

func uploadOwner(repo, id string, key []byte) (string, string, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 3 || len(parts[1]) != 32 || !auth.Verify(key, "upload", []byte(repo+"\n"+parts[0]+"."+parts[1]), parts[2]) {
		return "", "", fmt.Errorf("invalid upload ID")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", err
	}
	host, port, err := net.SplitHostPort(string(b))
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return "", "", fmt.Errorf("invalid upload owner")
	}
	return string(b), "registryless-upload-" + parts[1], nil
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, repo, id string) {
	key, err := s.Keys.Key(r.Context(), Namespace(repo), "push")
	if err != nil {
		fail(w, 503, "UNAVAILABLE", "credential unavailable")
		return
	}
	if id == "" {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		id = s.uploadID(repo, key)
		_, leaseID, _ := uploadOwner(repo, id, key)
		ctx, err := s.Store.NewLease(r.Context(), leaseID)
		if err != nil {
			s.readError(w, err)
			return
		}
		cw, err := content.OpenWriter(ctx, s.Store.Client.ContentStore(), content.WithRef(leaseID))
		if err != nil {
			s.readError(w, err)
			return
		}
		if err := cw.Close(); err != nil {
			s.readError(w, err)
			return
		}
		// Mount requests deliberately fall back to ordinary upload (202).
		if r.URL.Query().Get("digest") == "" {
			s.uploadResponse(w, repo, id, 0, 202)
			return
		}
		// Monolithic POST with ?digest= includes the complete blob body.
		r.Method = http.MethodPut
	}
	owner, leaseID, err := uploadOwner(repo, id, key)
	if err != nil {
		fail(w, 404, "BLOB_UPLOAD_UNKNOWN", "unknown upload")
		return
	}
	if owner != s.Address {
		s.proxyUpload(w, r, owner)
		return
	}
	ctx := leases.WithLease(r.Context(), leaseID)
	status, err := s.Store.Client.ContentStore().Status(ctx, leaseID)
	if err != nil || time.Since(status.StartedAt) > s.Store.TTL {
		fail(w, 404, "BLOB_UPLOAD_UNKNOWN", "upload expired or unknown")
		return
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		s.uploadResponse(w, repo, id, status.Offset, 204)
		return
	}
	if r.Method == "DELETE" {
		if err := s.Store.Client.ContentStore().Abort(ctx, leaseID); err != nil {
			s.readError(w, err)
			return
		}
		if err := s.Store.DropLease(ctx, leaseID); err != nil {
			s.readError(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.Method != "PATCH" && r.Method != "PUT" {
		w.WriteHeader(405)
		return
	}
	if value := r.Header.Get("Content-Range"); value != "" {
		start, _, ok := strings.Cut(value, "-")
		n, err := strconv.ParseInt(start, 10, 64)
		if !ok || err != nil || n != status.Offset {
			fail(w, 416, "RANGE_INVALID", "upload offset mismatch")
			return
		}
	}
	cw, err := content.OpenWriter(ctx, s.Store.Client.ContentStore(), content.WithRef(leaseID))
	if err != nil {
		s.readError(w, err)
		return
	}
	defer cw.Close()
	n, err := io.Copy(cw, http.MaxBytesReader(w, r.Body, s.MaxBlob-status.Offset))
	if err != nil {
		fail(w, 413, "SIZE_INVALID", "upload failed or exceeds size limit")
		return
	}
	if r.Method == "PATCH" {
		s.uploadResponse(w, repo, id, status.Offset+n, 202)
		return
	}
	dgst, err := digest.Parse(r.URL.Query().Get("digest"))
	if err != nil || dgst.Algorithm() != digest.SHA256 {
		fail(w, 400, "DIGEST_INVALID", "SHA-256 digest required")
		return
	}
	desc := ocispec.Descriptor{Digest: dgst, Size: status.Offset + n}
	if err := cw.Commit(ctx, desc.Size, dgst); err != nil && !errdefs.IsAlreadyExists(err) {
		fail(w, 400, "DIGEST_INVALID", "content digest mismatch")
		return
	}
	if err := s.Store.Mark(ctx, repo, desc, nil); err != nil {
		s.readError(w, err)
		return
	}
	// Retain the expiring upload lease until publication protects the blob.
	if err := s.Publisher.Publish(repo, "", desc); err != nil {
		s.Log.Warn("multicast publication deferred to future push", "error", err)
	}
	w.Header().Set("Docker-Content-Digest", dgst.String())
	w.Header().Set("Location", "/v2/"+repo+"/blobs/"+dgst.String())
	w.WriteHeader(201)
}

func (s *Server) uploadResponse(w http.ResponseWriter, repo, id string, offset int64, status int) {
	w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+id)
	w.Header().Set("Docker-Upload-UUID", id)
	end := max(int64(0), offset-1)
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (s *Server) proxyUpload(w http.ResponseWriter, r *http.Request, owner string) {
	// Only signed owner addresses reach here. Never forward credentials through
	// a redirect, or follow redirects returned by an owner.
	u := url.URL{Scheme: "http", Host: owner, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		s.readError(w, err)
		return
	}
	for _, name := range []string{"Authorization", "Content-Type", "Content-Range"} {
		req.Header.Set(name, r.Header.Get(name))
	}
	req.ContentLength = r.ContentLength
	resp, err := s.Proxy.Do(req)
	if err != nil {
		s.Log.Warn("upload owner request failed", "owner", owner, "error", err)
		fail(w, 502, "UNAVAILABLE", "upload owner unavailable; restart upload")
		return
	}
	defer resp.Body.Close()
	for _, name := range []string{"Location", "Range", "Docker-Upload-UUID", "Docker-Content-Digest", "Content-Type", "Content-Length"} {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.Log.Warn("upload forwarding interrupted", "error", err)
	}
}

func (s *Server) manifest(w http.ResponseWriter, r *http.Request, repo, ref string) {
	if _, err := reference.WithTag(mustRepo(repo), ref); err != nil {
		if d, e := digest.Parse(ref); e != nil || d.Algorithm() != digest.SHA256 {
			fail(w, 400, "TAG_INVALID", "invalid tag or digest")
			return
		}
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		desc, err := s.Store.Resolve(r.Context(), repo, ref)
		if err != nil {
			s.readError(w, err)
			return
		}
		w.Header().Set("Content-Type", desc.MediaType)
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())
		w.Header().Set("Content-Length", strconv.FormatInt(desc.Size, 10))
		if r.Method == "HEAD" {
			w.WriteHeader(200)
			return
		}
		ra, err := s.Store.Client.ContentStore().ReaderAt(r.Context(), desc)
		if err != nil {
			s.readError(w, err)
			return
		}
		defer ra.Close()
		if _, err := io.Copy(w, io.NewSectionReader(ra, 0, ra.Size())); err != nil {
			s.Log.Warn("manifest response interrupted", "error", err)
		}
		return
	}
	if r.Method != "PUT" {
		w.WriteHeader(405)
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !store.IsManifest(mt) {
		fail(w, 400, "MANIFEST_INVALID", "only single-platform image manifests supported")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, store.ManifestLimit))
	if err != nil {
		fail(w, 413, "MANIFEST_INVALID", "manifest too large")
		return
	}
	desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data)), MediaType: mt}
	if d, err := digest.Parse(ref); err == nil && d != desc.Digest {
		fail(w, 400, "DIGEST_INVALID", "manifest digest mismatch")
		return
	}
	id := "registryless-manifest-" + randomID()
	ctx, err := s.Store.NewLease(r.Context(), id)
	if err != nil {
		s.readError(w, err)
		return
	}
	if err := s.Store.Put(ctx, repo, id, desc, strings.NewReader(string(data))); err != nil {
		s.readError(w, err)
		return
	}
	// Ingress may put the manifest on a different node than its layer uploads.
	// Wait for the other publishers' staging content before linking the image.
	if err := s.awaitChildren(ctx, repo, data); err != nil {
		s.Log.Warn("manifest dependencies unavailable", "repository", repo, "error", err)
		fail(w, 400, "MANIFEST_BLOB_UNKNOWN", "manifest dependencies unavailable")
		return
	}
	if err := s.Store.Publish(ctx, repo, ref, desc); err != nil {
		s.Log.Warn("manifest rejected", "repository", repo, "error", err)
		fail(w, 400, "MANIFEST_INVALID", "manifest dependencies, platform or unpack invalid")
		return
	}
	if err := s.Publisher.Publish(repo, ref, desc); err != nil {
		s.Log.Warn("multicast queue full", "error", err)
		if s.PushSync {
			fail(w, 503, "UNAVAILABLE", "distribution queue unavailable; retry manifest push")
			return
		}
	}
	if s.PushSync {
		if s.Barrier == nil {
			fail(w, 503, "UNAVAILABLE", "synchronous distribution is not configured")
			return
		}
		if err := s.Barrier.Wait(ctx, repo, ref, desc); err != nil {
			s.Log.Warn("push synchronization failed", "repository", repo, "error", err)
			fail(w, 503, "UNAVAILABLE", "image not ready on all selected nodes; retry manifest push")
			return
		}
	}
	w.Header().Set("Docker-Content-Digest", desc.Digest.String())
	w.Header().Set("Location", "/v2/"+repo+"/manifests/"+desc.Digest.String())
	w.WriteHeader(201)
}

func (s *Server) awaitChildren(ctx context.Context, repo string, data []byte) error {
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != 2 || manifest.Config.Digest == "" {
		return fmt.Errorf("invalid image manifest")
	}
	children := append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...)
	for _, d := range children {
		if d.Digest.Validate() != nil || d.Digest.Algorithm() != digest.SHA256 || d.Size < 0 || d.Size > s.MaxBlob {
			return fmt.Errorf("invalid child descriptor")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for _, d := range children {
		for {
			info, err := s.Store.Info(ctx, repo, d.Digest)
			if err == nil {
				if info.Size != d.Size {
					return fmt.Errorf("child size mismatch")
				}
				break
			}
			if !errdefs.IsNotFound(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	return nil
}

func mustRepo(repo string) reference.Named { r, _ := reference.WithName(repo); return r }

func ReadinessSignature(key []byte, repo, ref, dgst string, expiry int64) string {
	return auth.MAC(key, "readiness", []byte(fmt.Sprintf("%s\n%s\n%s\n%d", repo, ref, dgst, expiry)))
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	repo, ref := q.Get("repo"), q.Get("ref")
	dgst, err := digest.Parse(strings.TrimPrefix(r.URL.Path, "/internal/ready/"))
	expiry, e := strconv.ParseInt(q.Get("expires"), 10, 64)
	if err != nil || e != nil || !ValidRepo(repo) || expiry < time.Now().Unix() || expiry > time.Now().Add(time.Hour).Unix() {
		w.WriteHeader(403)
		return
	}
	key, err := s.Keys.Key(r.Context(), Namespace(repo), "push")
	want := ReadinessSignature(key, repo, ref, dgst.String(), expiry)
	if err != nil || len(want) != len(q.Get("signature")) || subtle.ConstantTimeCompare([]byte(want), []byte(q.Get("signature"))) != 1 {
		w.WriteHeader(403)
		return
	}
	ready, err := s.Store.Ready(r.Context(), repo, ref, dgst)
	if err != nil {
		s.Log.Warn("readiness inspection failed", "error", err)
		w.WriteHeader(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"platform": s.Store.Platform, "ready": ready})
}
