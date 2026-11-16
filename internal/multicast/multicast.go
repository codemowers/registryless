package multicast

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/metrics"
	"github.com/codemowers/registryless/internal/registry"
	"github.com/codemowers/registryless/internal/store"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/net/ipv4"
)

type publication struct {
	repo, ref, lease string
	desc             ocispec.Descriptor
}
type packet struct {
	kind   byte
	offset uint64
	data   []byte
}
type transfer struct {
	a       Announcement
	source  net.IP
	packets chan packet
}

type Agent struct {
	Store          *store.Store
	Keys           auth.Keys
	Metrics        *metrics.Metrics
	Log            *slog.Logger
	Address        string
	MaxBlob        int64
	BytesPerSecond int64
	ReorderWindow  time.Duration
	Timeout        time.Duration
	conn           *net.UDPConn
	sendConn       *net.UDPConn
	group          *net.UDPAddr
	queue          chan publication
	mu             sync.Mutex
	active         map[ID]*transfer
	seen           map[ID]time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	client         *http.Client
	wg             sync.WaitGroup
}

func (a *Agent) Open(ctx context.Context, iface *net.Interface, group net.IP, port, ttl int) error {
	a.group = &net.UDPAddr{IP: group, Port: port}
	conn, err := net.ListenMulticastUDP("udp4", iface, a.group)
	if err != nil {
		return err
	}
	a.conn = conn
	host, _, err := net.SplitHostPort(a.Address)
	if err != nil {
		conn.Close()
		return err
	}
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		conn.Close()
		return err
	}
	a.sendConn = tx
	pc := ipv4.NewPacketConn(tx)
	for _, err := range []error{pc.SetMulticastInterface(iface), pc.SetMulticastTTL(ttl), pc.SetMulticastLoopback(true), conn.SetReadBuffer(4 << 20)} {
		if err != nil {
			conn.Close()
			tx.Close()
			return err
		}
	}
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.queue = make(chan publication, 64)
	a.active = make(map[ID]*transfer)
	a.seen = make(map[ID]time.Time)
	a.client = &http.Client{Timeout: a.Timeout, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 8, ResponseHeaderTimeout: 10 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}

func (a *Agent) Close() error {
	a.cancel()
	err := a.conn.Close()
	txErr := a.sendConn.Close()
	if err != nil {
		return err
	}
	return txErr
}

func (a *Agent) Run() error {
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.sendLoop() }()
	defer a.wg.Wait()
	defer a.cancel()
	buf := make([]byte, HeaderSize+ChunkSize+1)
	for {
		n, source, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			if a.ctx.Err() != nil {
				return nil
			}
			return err
		}
		kind, id, offset, payload, err := Decode(buf[:n])
		if err != nil {
			continue
		}
		if kind == Announce {
			a.Log.Debug("multicast announcement datagram", "source", source.String())
			a.accept(id, source.IP, payload)
			continue
		}
		a.mu.Lock()
		t := a.active[id]
		a.mu.Unlock()
		if t == nil || !source.IP.Equal(t.source) {
			continue
		}
		p := packet{kind, offset, append([]byte(nil), payload...)}
		select {
		case t.packets <- p:
		default:
			a.Metrics.Dropped.WithLabelValues(registry.Namespace(t.a.Repository)).Inc()
		}
	}
}

func (a *Agent) Publish(repo, ref string, desc ocispec.Descriptor) error {
	id := "registryless-send-" + NewID().String()
	ctx, err := a.Store.NewLease(a.ctx, id)
	if err != nil {
		return err
	}
	if err := a.Store.Client.LeasesService().AddResource(ctx, leases.Lease{ID: id}, leases.Resource{Type: "content", ID: desc.Digest.String()}); err != nil {
		return err
	}
	select {
	case a.queue <- publication{repo, ref, id, desc}:
		return nil
	default:
		if err := a.Store.DropLease(ctx, id); err != nil {
			a.Log.Error("release full queue lease", "error", err)
		}
		return fmt.Errorf("multicast queue full")
	}
}

func (a *Agent) sendLoop() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case p := <-a.queue:
			ctx, cancel := context.WithTimeout(a.ctx, a.Timeout)
			if err := a.send(ctx, p); err != nil {
				a.Log.Warn("multicast send failed", "repository", p.repo, "error", err)
			}
			cancel()
			if err := a.Store.DropLease(a.ctx, p.lease); err != nil && a.ctx.Err() == nil {
				a.Log.Error("release send lease", "error", err)
			}
		}
	}
}

func (a *Agent) send(ctx context.Context, p publication) error {
	id := NewID()
	key, err := a.Keys.Key(ctx, registry.Namespace(p.repo), "push")
	if err != nil {
		return err
	}
	meta := Announcement{ID: id.String(), Platform: a.Store.Platform, Repository: p.repo, Reference: p.ref, Descriptor: p.desc, Source: a.Address, Expires: time.Now().Add(a.Timeout + time.Minute).Unix()}
	a.Log.Debug("sending multicast content", "repository", p.repo, "source", a.Address, "group", a.group.String())
	b, err := sign(meta, key)
	if err != nil {
		return err
	}
	send := func(kind byte, offset uint64, payload []byte) error {
		_, err := a.sendConn.WriteToUDP(Encode(kind, id, offset, payload), a.group)
		return err
	}
	if err := send(Announce, 0, b); err != nil {
		return err
	}
	ra, err := a.Store.Client.ContentStore().ReaderAt(ctx, p.desc)
	if err != nil {
		return err
	}
	defer ra.Close()
	buf := make([]byte, ChunkSize)
	start := time.Now()
	for offset := int64(0); offset < p.desc.Size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := ra.ReadAt(buf[:min(int64(ChunkSize), p.desc.Size-offset)], offset)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		if err := send(Data, uint64(offset), buf[:n]); err != nil {
			return err
		}
		offset += int64(n)
		if (offset/ChunkSize)%32 == 0 {
			delay := time.Duration(float64(offset)/float64(a.BytesPerSecond)*float64(time.Second)) - time.Since(start)
			if delay > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
			}
		}
	}
	// Repeat the announcement at completion: if the opening datagram was lost,
	// the receiver can still repair the complete blob using the publisher.
	for range 3 {
		if err := send(Announce, 0, b); err != nil {
			return err
		}
		if err := send(Done, 0, nil); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

func (a *Agent) accept(id ID, source net.IP, payload []byte) {
	a.mu.Lock()
	_, active := a.active[id]
	expiry, seen := a.seen[id]
	full := len(a.active) >= 32
	a.mu.Unlock()
	if active || (seen && time.Now().Before(expiry)) || full {
		return
	}
	// Parse only to find the credential. The signed body is fully validated next.
	var envelope signed
	var untrusted Announcement
	if json.Unmarshal(payload, &envelope) != nil || json.Unmarshal(envelope.Body, &untrusted) != nil || untrusted.Source == a.Address || untrusted.Platform != a.Store.Platform || !registry.ValidRepo(untrusted.Repository) {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	key, err := a.Keys.Key(ctx, registry.Namespace(untrusted.Repository), "push")
	cancel()
	if err != nil {
		return
	}
	meta, err := verify(payload, key, id, a.Store.Platform, source, a.MaxBlob)
	if err != nil {
		a.Log.Debug("discard multicast announcement", "error", err)
		return
	}
	a.Log.Debug("accepted multicast announcement", "repository", meta.Repository, "digest", meta.Descriptor.Digest)
	t := &transfer{a: meta, source: append(net.IP(nil), source...), packets: make(chan packet, 256)}
	a.mu.Lock()
	for id, expiry := range a.seen {
		if time.Now().After(expiry) {
			delete(a.seen, id)
		}
	}
	if len(a.seen) >= 4096 {
		a.mu.Unlock()
		return
	}
	a.active[id] = t
	a.seen[id] = time.Unix(meta.Expires, 0)
	a.mu.Unlock()
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() { a.mu.Lock(); delete(a.active, id); a.mu.Unlock() }()
		a.receive(id, t, key)
	}()
}

func (a *Agent) receive(id ID, t *transfer, key []byte) {
	ns := registry.Namespace(t.a.Repository)
	outcome := "failed"
	defer func() { a.Metrics.Transfers.WithLabelValues(ns, outcome).Inc() }()
	ctx, cancel := context.WithTimeout(a.ctx, a.Timeout)
	defer cancel()
	leaseID := "registryless-receive-" + id.String()
	ctx, err := a.Store.NewLease(ctx, leaseID)
	if err != nil {
		a.Log.Error("create receive lease", "error", err)
		return
	}
	desc := t.a.Descriptor
	if _, err := a.Store.Info(ctx, t.a.Repository, desc.Digest); err == nil {
		if t.a.Reference != "" {
			if err := a.publishReceived(ctx, t.a, key); err != nil {
				a.Log.Warn("received manifest rejected", "error", err)
				return
			}
		}
		outcome = "already_present"
		return
	}
	ref := leaseID
	// Ingest from offset zero. Supplying the expected digest at open can expose
	// an already-complete shared-namespace writer; verify the digest at commit.
	cw, err := a.Store.Client.ContentStore().Writer(ctx, content.WithRef(ref), content.WithDescriptor(ocispec.Descriptor{Size: desc.Size}))
	if errdefs.IsAlreadyExists(err) {
		if err := a.Store.Mark(ctx, t.a.Repository, desc, nil); err != nil {
			return
		}
		if t.a.Reference != "" {
			if err := a.publishReceived(ctx, t.a, key); err != nil {
				return
			}
		}
		outcome = "already_present"
		return
	}
	if err != nil {
		a.Log.Error("open receive writer", "error", err)
		return
	}
	defer cw.Close()
	defer func() {
		if outcome == "failed" {
			if err := a.Store.Client.ContentStore().Abort(a.ctx, ref); err != nil && !errdefs.IsNotFound(err) && a.ctx.Err() == nil {
				a.Log.Warn("abort receive", "error", err)
			}
		}
	}()
	// A bitmap measures unique datagrams independently of the bounded reorder
	// buffer. Thus packets discarded locally are not misreported as network loss.
	count := (desc.Size + ChunkSize - 1) / ChunkSize
	bitmap := make([]byte, (count+7)/8)
	pending := make(map[uint64][]byte)
	var offset, received int64
	var settle <-chan time.Time
	quiet := time.NewTimer(5 * time.Second)
	defer quiet.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			return
		case <-settle:
			break loop
		case <-quiet.C:
			break loop
		case p := <-t.packets:
			if p.kind == Done {
				if settle == nil {
					settle = time.After(a.ReorderWindow)
				}
				continue
			}
			if p.kind != Data || p.offset%ChunkSize != 0 || p.offset >= uint64(desc.Size) || len(p.data) != int(min(int64(ChunkSize), desc.Size-int64(p.offset))) {
				continue
			}
			quiet.Reset(5 * time.Second)
			i := p.offset / ChunkSize
			mask := byte(1 << (i % 8))
			if bitmap[i/8]&mask != 0 {
				a.Metrics.Duplicates.WithLabelValues(ns).Add(float64(len(p.data)))
				continue
			}
			bitmap[i/8] |= mask
			received += int64(len(p.data))
			a.Metrics.Received.WithLabelValues(ns).Add(float64(len(p.data)))
			if p.offset != uint64(offset) {
				if len(pending) < 256 {
					pending[p.offset] = p.data
				} else {
					a.Metrics.Dropped.WithLabelValues(ns).Inc()
				}
				continue
			}
			for data := p.data; data != nil; data = pending[uint64(offset)] {
				delete(pending, uint64(offset))
				n, err := cw.Write(data)
				if err != nil || n != len(data) {
					return
				}
				offset += int64(n)
			}
		}
	}
	a.Metrics.Expected.WithLabelValues(ns).Add(float64(desc.Size))
	a.Metrics.Missing.WithLabelValues(ns).Add(float64(desc.Size - received))
	outcome = "complete"
	if offset < desc.Size {
		outcome = "failed"
		if err := a.repair(ctx, t.a, key, cw, offset); err != nil {
			a.Log.Warn("HTTP repair failed", "repository", t.a.Repository, "error", err)
			return
		}
		outcome = "repaired"
	}
	if err := cw.Commit(ctx, desc.Size, desc.Digest); err != nil && !errdefs.IsAlreadyExists(err) {
		outcome = "failed"
		a.Log.Warn("received blob failed digest verification", "repository", t.a.Repository, "error", err)
		return
	}
	if err := a.Store.Mark(ctx, t.a.Repository, desc, nil); err != nil {
		outcome = "failed"
		return
	}
	if t.a.Reference != "" {
		if err := a.publishReceived(ctx, t.a, key); err != nil {
			outcome = "failed"
			a.Log.Warn("received image publication failed", "repository", t.a.Repository, "error", err)
			return
		}
	}
	a.Log.Info("received content", "repository", t.a.Repository, "digest", desc.Digest, "multicast_bytes", received, "size", desc.Size, "outcome", outcome)
}

func (a *Agent) repair(ctx context.Context, meta Announcement, key []byte, dst io.Writer, offset int64) error {
	u := url.URL{Scheme: "http", Host: meta.Source, Path: "/internal/blobs/" + meta.Descriptor.Digest.String()}
	q := u.Query()
	q.Set("repo", meta.Repository)
	q.Set("expires", strconv.FormatInt(meta.Expires, 10))
	q.Set("signature", registry.Ticket(key, meta.Repository, meta.Descriptor.Digest, meta.Expires))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	remaining := meta.Descriptor.Size - offset
	if resp.StatusCode != 206 || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", offset, meta.Descriptor.Size-1, meta.Descriptor.Size) {
		return fmt.Errorf("invalid repair response: %d", resp.StatusCode)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, remaining))
	a.Metrics.Repair.WithLabelValues(registry.Namespace(meta.Repository)).Add(float64(n))
	if err != nil {
		return err
	}
	if n != remaining {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (a *Agent) publishReceived(ctx context.Context, meta Announcement, key []byte) error {
	// The small manifest may overtake its layer receive workers. Fetch any missing
	// dependencies from the authenticated publisher before registering the image.
	data, err := content.ReadBlob(ctx, a.Store.Client.ContentStore(), meta.Descriptor)
	if err != nil {
		return err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	for _, child := range append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...) {
		if child.Size < 0 || child.Size > a.MaxBlob || child.Digest.Validate() != nil {
			return fmt.Errorf("invalid child descriptor")
		}
		if _, err := a.Store.Info(ctx, meta.Repository, child.Digest); err == nil {
			continue
		}
		id := "registryless-repair-" + NewID().String()
		cw, err := a.Store.Client.ContentStore().Writer(ctx, content.WithRef(id), content.WithDescriptor(ocispec.Descriptor{Size: child.Size}))
		if errdefs.IsAlreadyExists(err) {
			if err := a.Store.Mark(ctx, meta.Repository, child, nil); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		childMeta := meta
		childMeta.Descriptor = child
		err = a.repair(ctx, childMeta, key, cw, 0)
		if err == nil {
			err = cw.Commit(ctx, child.Size, child.Digest)
		} else {
			cw.Close()
			_ = a.Store.Client.ContentStore().Abort(ctx, id)
		}
		if err != nil && !errdefs.IsAlreadyExists(err) {
			return err
		}
		if err := a.Store.Mark(ctx, meta.Repository, child, nil); err != nil {
			return err
		}
	}
	return a.Store.Publish(ctx, meta.Repository, meta.Reference, meta.Descriptor)
}
