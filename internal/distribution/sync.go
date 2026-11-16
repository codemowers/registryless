// Package distribution implements the optional final-manifest push barrier.
package distribution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/registry"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	coreapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type Peer struct{ Name, Address string }
type Barrier struct {
	Core                          corev1.CoreV1Interface
	Keys                          auth.Keys
	Namespace, Selector, Platform string
	Port                          int
	Timeout                       time.Duration
	Client                        *http.Client
	// Discover is injectable for deterministic tests; production uses Pods/Nodes.
	Discover func(context.Context) ([]Peer, error)
}

func (b *Barrier) peers(ctx context.Context) ([]Peer, error) {
	if b.Discover != nil {
		return b.Discover(ctx)
	}
	pods, err := b.Core.Pods(b.Namespace).List(ctx, metav1.ListOptions{LabelSelector: b.Selector})
	if err != nil {
		return nil, err
	}
	nodes, err := b.Core.Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	platform, err := platforms.Parse(b.Platform)
	if err != nil {
		return nil, err
	}
	eligible := map[string]bool{}
	for _, n := range nodes.Items {
		eligible[n.Name] = n.Status.NodeInfo.Architecture == platform.Architecture && n.Status.NodeInfo.OperatingSystem == platform.OS
	}
	var result []Peer
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil || p.Status.Phase == coreapi.PodSucceeded || p.Status.Phase == coreapi.PodFailed || !eligible[p.Spec.NodeName] {
			continue
		}
		if p.Status.PodIP == "" {
			return nil, fmt.Errorf("agent %s has no address", p.Name)
		}
		result = append(result, Peer{Name: p.Name, Address: net.JoinHostPort(p.Status.PodIP, strconv.Itoa(b.Port))})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no platform agents discovered")
	}
	return result, nil
}

func (b *Barrier) Wait(ctx context.Context, repo, ref string, desc ocispec.Descriptor) error {
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	peers, err := b.peers(ctx)
	if err != nil {
		return fmt.Errorf("discover synchronization targets: %w", err)
	}
	if len(peers) == 0 {
		return fmt.Errorf("empty synchronization target set")
	}
	key, err := b.Keys.Key(ctx, registry.Namespace(repo), "push")
	if err != nil {
		return err
	}
	expires := time.Now().Add(b.Timeout + time.Minute).Unix()
	if expires > time.Now().Add(time.Hour).Unix() {
		return fmt.Errorf("sync timeout must be less than one hour")
	}
	client := b.Client
	if client == nil {
		transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
		defer transport.CloseIdleConnections()
		client = &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	var matchingPlatform atomic.Bool
	check := func(p Peer) (bool, error) {
		u := url.URL{Scheme: "http", Host: p.Address, Path: "/internal/ready/" + desc.Digest.String()}
		q := u.Query()
		q.Set("repo", repo)
		q.Set("ref", ref)
		q.Set("expires", strconv.FormatInt(expires, 10))
		q.Set("signature", registry.ReadinessSignature(key, repo, ref, desc.Digest.String(), expires))
		u.RawQuery = q.Encode()
		r, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(r)
		if err != nil {
			return false, nil
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return false, nil
		}
		var status struct {
			Platform string `json:"platform"`
			Ready    bool   `json:"ready"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status); err != nil {
			return false, nil
		}
		// CPU variants are checked on the authenticated response, not inferred
		// solely from Kubernetes' coarser OS/architecture node labels.
		if status.Platform != b.Platform {
			return true, nil
		}
		matchingPlatform.Store(true)
		return status.Ready, nil
	}
	pending := map[string]Peer{}
	for _, p := range peers {
		pending[p.Name] = p
	}
	for len(pending) > 0 {
		var mu sync.Mutex
		var wg sync.WaitGroup
		slots := make(chan struct{}, 8)
		batch := make([]Peer, 0, len(pending))
		for _, peer := range pending {
			batch = append(batch, peer)
		}
		for _, peer := range batch {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return fmt.Errorf("push synchronization timed out: %w", ctx.Err())
			}
			wg.Add(1)
			go func(p Peer) {
				defer wg.Done()
				defer func() { <-slots }()
				ready, _ := check(p)
				if ready {
					mu.Lock()
					delete(pending, p.Name)
					mu.Unlock()
				}
			}(peer)
		}
		wg.Wait()
		if len(pending) == 0 {
			if !matchingPlatform.Load() {
				return fmt.Errorf("no agents acknowledged the publishing platform")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			names := make([]string, 0, len(pending))
			for name := range pending {
				names = append(names, name)
			}
			return fmt.Errorf("pending agents %s: %w", strings.Join(names, ","), ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil
}
