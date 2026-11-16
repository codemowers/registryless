package distribution

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codemowers/registryless/internal/registry"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type testKeys struct{}

func (testKeys) Key(context.Context, string, string) ([]byte, error) {
	return []byte("test-distribution-key"), nil
}

func TestBarrierWaitsForEveryAcknowledgement(t *testing.T) {
	var ready atomic.Bool
	var hits atomic.Int64
	desc := ocispec.Descriptor{Digest: digest.FromString("manifest")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		expiry, _ := strconv.ParseInt(q.Get("expires"), 10, 64)
		if q.Get("signature") != registry.ReadinessSignature([]byte("test-distribution-key"), "demo/app", "dev", desc.Digest.String(), expiry) {
			t.Error("readiness request not authenticated")
			w.WriteHeader(403)
			return
		}
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "linux/amd64", "ready": ready.Load()})
	}))
	defer server.Close()
	b := &Barrier{Keys: testKeys{}, Platform: "linux/amd64", Timeout: 2 * time.Second, Discover: func(context.Context) ([]Peer, error) {
		return []Peer{{Name: "node-a", Address: strings.TrimPrefix(server.URL, "http://")}}, nil
	}}
	done := make(chan error, 1)
	go func() { done <- b.Wait(context.Background(), "demo/app", "dev", desc) }()
	deadline := time.Now().Add(time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("no readiness request")
	}
	select {
	case err := <-done:
		t.Fatal("barrier completed before acknowledgement", err)
	default:
	}
	ready.Store(true)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBarrierTimeoutAndEmptyTargetsFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "linux/amd64", "ready": false})
	}))
	defer server.Close()
	b := &Barrier{Keys: testKeys{}, Platform: "linux/amd64", Timeout: 40 * time.Millisecond, Discover: func(context.Context) ([]Peer, error) {
		return []Peer{{Name: "missing-image", Address: strings.TrimPrefix(server.URL, "http://")}}, nil
	}}
	if err := b.Wait(context.Background(), "demo/app", "dev", ocispec.Descriptor{Digest: digest.FromString("missing")}); err == nil {
		t.Fatal("incomplete distribution reported success")
	}
	b.Discover = func(context.Context) ([]Peer, error) { return nil, nil }
	if err := b.Wait(context.Background(), "demo/app", "dev", ocispec.Descriptor{}); err == nil {
		t.Fatal("empty target set reported success")
	}
}
