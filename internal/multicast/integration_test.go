package multicast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codemowers/registryless/internal/metrics"
	"github.com/codemowers/registryless/internal/network"
	"github.com/codemowers/registryless/internal/registry"
	"github.com/codemowers/registryless/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/prometheus/client_golang/prometheus"
)

type testKeys struct{}

var pushKey = []byte("push-012345678901234567890123456789")
var pullKey = []byte("pull-012345678901234567890123456789")

func (testKeys) Key(_ context.Context, ns, role string) ([]byte, error) {
	if ns != "project" {
		return nil, fmt.Errorf("namespace not enabled")
	}
	if role == "push" {
		return pushKey, nil
	}
	return pullKey, nil
}

type discardPublisher struct{}

func (discardPublisher) Publish(string, string, ocispec.Descriptor) error { return nil }

func testStore(t *testing.T) *store.Store {
	t.Helper()
	addr := os.Getenv("REGISTRYLESS_TEST_CONTAINERD")
	if addr == "" {
		t.Skip("set REGISTRYLESS_TEST_CONTAINERD to an isolated containerd socket")
	}
	ns := "registryless-test-" + NewID().String()
	c, err := containerd.New(addr, containerd.WithDefaultNamespace(ns))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &store.Store{Client: c, Host: "less.example.test", Platform: network.Platform(platforms.DefaultSpec()), TTL: time.Minute}
}
func testHTTP(t *testing.T, s *store.Store, p registry.Publisher, ip string) *httptest.Server {
	t.Helper()
	h := &registry.Server{Store: s, Keys: testKeys{}, Publisher: p, MaxBlob: 4 << 20, Log: slog.Default(), Proxy: &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	ts := httptest.NewUnstartedServer(h)
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	ts.Listener = l
	h.Address = l.Addr().String()
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}
func request(t *testing.T, method, u string, body []byte, password string, headers map[string]string, want int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("project", password)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("%s %s: got %d, want %d: %s", method, u, resp.StatusCode, want, b)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}
func counter(t *testing.T, r *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			var total float64
			for _, m := range f.Metric {
				total += m.GetCounter().GetValue()
			}
			return total
		}
	}
	return 0
}

func TestReceiveLossReorderAndHTTPRepair(t *testing.T) {
	source, destination := testStore(t), testStore(t)
	data := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz"), 200)
	desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data))}
	ctx, err := source.NewLease(context.Background(), "source-"+NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Put(ctx, "project/api", "blob-"+NewID().String(), desc, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	ts := testHTTP(t, source, discardPublisher{}, "127.0.0.1")
	r := prometheus.NewRegistry()
	m := metrics.New(r)
	a := &Agent{Store: destination, Keys: testKeys{}, Metrics: m, Log: slog.Default(), MaxBlob: 4 << 20, ReorderWindow: 10 * time.Millisecond, Timeout: 5 * time.Second, ctx: context.Background(), client: ts.Client()}
	id := NewID()
	meta := Announcement{ID: id.String(), Platform: source.Platform, Repository: "project/api", Descriptor: desc, Source: strings.TrimPrefix(ts.URL, "http://"), Expires: time.Now().Add(time.Minute).Unix()}
	tr := &transfer{a: meta, packets: make(chan packet, 20)}
	// Deliver 2 before 0, duplicate 0, lose 1, then deliver the remaining data.
	for _, i := range []int{2, 0, 0, 3, 4} {
		start := i * ChunkSize
		end := min(start+ChunkSize, len(data))
		tr.packets <- packet{kind: Data, offset: uint64(start), data: append([]byte(nil), data[start:end]...)}
	}
	tr.packets <- packet{kind: Done}
	a.receive(id, tr, pushKey)
	got, err := content.ReadBlob(context.Background(), destination.Client.ContentStore(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("repaired content mismatch")
	}
	for name, want := range map[string]float64{"registryless_receive_missing_bytes_total": ChunkSize, "registryless_receive_duplicate_bytes_total": ChunkSize, "registryless_receive_multicast_bytes_total": float64(len(data) - ChunkSize), "registryless_receive_http_repair_bytes_total": float64(len(data) - ChunkSize)} {
		if got := counter(t, r, name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
}

func TestRegistryAuthUploadAndMulticast(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	source, destination := testStore(t), testStore(t)
	iface, ip, err := network.Discover(os.Getenv("REGISTRYLESS_TEST_INTERFACE"), "")
	if os.Getenv("REGISTRYLESS_TEST_INTERFACE") == "lo" {
		iface, err = net.InterfaceByName("lo")
		ip = net.IPv4(127, 0, 0, 1)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newAgent := func(s *store.Store) *Agent {
		return &Agent{Store: s, Keys: testKeys{}, Metrics: metrics.New(prometheus.NewRegistry()), Log: slog.Default(), MaxBlob: 4 << 20, BytesPerSecond: 1 << 20, ReorderWindow: 20 * time.Millisecond, Timeout: 5 * time.Second}
	}
	sender, receiver := newAgent(source), newAgent(destination)
	ts := testHTTP(t, source, sender, ip.String())
	other := testHTTP(t, destination, receiver, ip.String())
	sender.Address = strings.TrimPrefix(ts.URL, "http://")
	receiver.Address = strings.TrimPrefix(other.URL, "http://")
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	group := network.Group("registryless-test/" + NewID().String())
	for _, a := range []*Agent{sender, receiver} {
		if err := a.Open(ctx, iface, group, port, 1); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- a.Run() }()
		t.Cleanup(func() {
			a.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("agent shutdown timed out")
			}
		})
	}
	request(t, "GET", ts.URL+"/v2/", nil, string(pullKey), nil, 200)
	request(t, "POST", ts.URL+"/v2/project/api/blobs/uploads/", nil, string(pullKey), nil, 401)
	request(t, "POST", ts.URL+"/v2/other/api/blobs/uploads/", nil, string(pushKey), nil, 401)
	layer := []byte("test layer content; unpack disabled for unprivileged test")
	config, _ := json.Marshal(ocispec.Image{Platform: platforms.DefaultSpec(), RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromBytes(layer)}}})
	var descriptors []ocispec.Descriptor
	for _, blob := range [][]byte{config, layer} {
		desc := ocispec.Descriptor{Digest: digest.FromBytes(blob), Size: int64(len(blob))}
		descriptors = append(descriptors, desc)
		resp := request(t, "POST", ts.URL+"/v2/project/api/blobs/uploads/", nil, string(pushKey), nil, 202)
		location := resp.Header.Get("Location")
		// The other node must forward this PATCH to the upload owner.
		request(t, "PATCH", other.URL+location, blob, string(pushKey), map[string]string{"Content-Type": "application/octet-stream"}, 202)
		request(t, "PUT", other.URL+location+"?digest="+desc.Digest.String(), nil, string(pushKey), nil, 201)
	}
	descriptors[0].MediaType = ocispec.MediaTypeImageConfig
	descriptors[1].MediaType = ocispec.MediaTypeImageLayer
	manifest := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: descriptors[0], Layers: descriptors[1:]}
	body, _ := json.Marshal(manifest)
	request(t, "PUT", other.URL+"/v2/project/api/manifests/dev", body, string(pushKey), map[string]string{"Content-Type": ocispec.MediaTypeImageManifest}, 201)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := destination.Resolve(ctx, "project/api", "dev")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("image was not distributed:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp := request(t, "GET", other.URL+"/v2/project/api/manifests/dev", nil, string(pullKey), nil, 200)
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, body) {
		t.Fatal("manifest changed in distribution")
	}
	images, err := destination.Client.ImageService().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		if image.Labels["codemowers.io/registryless"] != "true" || image.Labels["codemowers.io/registryless.repository"] != "project/api" {
			t.Fatal("missing ownership labels", image.Labels)
		}
		if image.Labels["io.cri-containerd.pinned"] != "" {
			t.Fatal("image was pinned")
		}
	}
	// Monolithic uploads and digest rejection are part of the push surface too.
	request(t, "POST", ts.URL+"/v2/project/api/blobs/uploads/?digest="+digest.FromBytes(layer).String(), layer, string(pushKey), nil, 201)
	request(t, "POST", ts.URL+"/v2/project/api/blobs/uploads/?digest="+digest.FromString("wrong").String(), layer, string(pushKey), nil, 400)
}
