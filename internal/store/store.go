// Package store keeps registry content and image records in containerd.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/codemowers/registryless/internal/network"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const ManifestLimit = 4 << 20

type Store struct {
	Client      *containerd.Client
	Host        string
	Platform    string
	Snapshotter string
	Unpack      bool
	TTL         time.Duration
}

func RepoLabel(repo string) string {
	h := sha256.Sum256([]byte(repo))
	return "registryless.io/repo." + hex.EncodeToString(h[:16])
}

func (s *Store) NewLease(ctx context.Context, id string) (context.Context, error) {
	_, err := s.Client.LeasesService().Create(ctx, leases.WithID(id), leases.WithExpiration(s.TTL))
	if err != nil {
		return ctx, err
	}
	return leases.WithLease(ctx, id), nil
}

func (s *Store) DropLease(ctx context.Context, id string) error {
	return s.Client.LeasesService().Delete(ctx, leases.Lease{ID: id})
}

func (s *Store) Mark(ctx context.Context, repo string, desc ocispec.Descriptor, links map[string]string) error {
	labels := map[string]string{RepoLabel(repo): "true", "codemowers.io/registryless": "true"}
	if desc.MediaType != "" {
		labels["registryless.io/media-type"] = desc.MediaType
	}
	for k, v := range links {
		labels[k] = v
	}
	paths := make([]string, 0, len(labels))
	for key := range labels {
		paths = append(paths, "labels."+key)
	}
	_, err := s.Client.ContentStore().Update(ctx, content.Info{Digest: desc.Digest, Labels: labels}, paths...)
	return err
}

func (s *Store) Info(ctx context.Context, repo string, dgst digest.Digest) (content.Info, error) {
	info, err := s.Client.ContentStore().Info(ctx, dgst)
	if err != nil {
		return info, err
	}
	if info.Labels[RepoLabel(repo)] != "true" {
		return content.Info{}, fmt.Errorf("repository content: %w", errdefs.ErrNotFound)
	}
	return info, nil
}

func (s *Store) Put(ctx context.Context, repo, id string, desc ocispec.Descriptor, r io.Reader) error {
	if err := content.WriteBlob(ctx, s.Client.ContentStore(), id, r, desc); err != nil {
		return err
	}
	return s.Mark(ctx, repo, desc, nil)
}

// Publish establishes the manifest's GC edges before registering image records.
// The upload credential authorizes publication; received peers validate it too.
func (s *Store) Publish(ctx context.Context, repo, ref string, desc ocispec.Descriptor) error {
	if desc.Size > ManifestLimit {
		return fmt.Errorf("manifest too large")
	}
	data, err := content.ReadBlob(ctx, s.Client.ContentStore(), desc)
	if err != nil {
		return err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.SchemaVersion != 2 || m.Config.Digest == "" || m.Subject != nil || m.ArtifactType != "" {
		return fmt.Errorf("only schema 2 runnable image manifests are supported")
	}
	children := append([]ocispec.Descriptor{m.Config}, m.Layers...)
	links := make(map[string]string, len(children))
	for i, child := range children {
		if child.Digest.Algorithm() != digest.SHA256 || child.Digest.Validate() != nil {
			return fmt.Errorf("invalid child digest")
		}
		info, err := s.Info(ctx, repo, child.Digest)
		if err != nil {
			return fmt.Errorf("missing child %s: %w", child.Digest, err)
		}
		if info.Size != child.Size {
			return fmt.Errorf("child size mismatch")
		}
		links[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = child.Digest.String()
	}
	configData, err := content.ReadBlob(ctx, s.Client.ContentStore(), m.Config)
	if err != nil {
		return err
	}
	var config ocispec.Image
	if err := json.Unmarshal(configData, &config); err != nil {
		return err
	}
	if network.Platform(config.Platform) != s.Platform {
		return fmt.Errorf("image platform %s differs from host %s", network.Platform(config.Platform), s.Platform)
	}
	if err := s.Mark(ctx, repo, desc, links); err != nil {
		return err
	}
	labels := map[string]string{"io.cri-containerd.image": "managed", "codemowers.io/registryless": "true", "codemowers.io/registryless.repository": repo}
	// Tag and digest references both resolve through the runtime's image service.
	for _, suffix := range []string{"@" + desc.Digest.String(), ":" + ref} {
		if suffix[0] == ':' && ref == desc.Digest.String() {
			continue
		}
		image := images.Image{Name: s.Host + "/" + repo + suffix, Target: desc, Labels: labels}
		created, err := s.Client.ImageService().Create(ctx, image)
		if errdefs.IsAlreadyExists(err) {
			created, err = s.Client.ImageService().Update(ctx, image, "target", "labels.io.cri-containerd.image", "labels.codemowers.io/registryless", "labels.codemowers.io/registryless.repository")
		}
		if err != nil {
			return err
		}
		if s.Unpack && suffix[0] == '@' {
			if err := containerd.NewImage(s.Client, created).Unpack(ctx, s.Snapshotter); err != nil {
				return fmt.Errorf("unpack image: %w", err)
			}
		}
	}
	return nil
}

func (s *Store) Resolve(ctx context.Context, repo, ref string) (ocispec.Descriptor, error) {
	if dgst, err := digest.Parse(ref); err == nil {
		info, err := s.Info(ctx, repo, dgst)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		mt := info.Labels["registryless.io/media-type"]
		if !IsManifest(mt) {
			return ocispec.Descriptor{}, errdefs.ErrNotFound
		}
		return ocispec.Descriptor{Digest: dgst, Size: info.Size, MediaType: mt}, nil
	}
	image, err := s.Client.ImageService().Get(ctx, s.Host+"/"+repo+":"+ref)
	return image.Target, err
}

func IsManifest(mt string) bool {
	return mt == ocispec.MediaTypeImageManifest || mt == "application/vnd.docker.distribution.manifest.v2+json"
}

// Ready acknowledges the current reference and unpacked snapshot. It does not pin.
func (s *Store) Ready(ctx context.Context, repo, ref string, dgst digest.Digest) (bool, error) {
	desc, err := s.Resolve(ctx, repo, ref)
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if desc.Digest != dgst {
		return false, nil
	}
	image, err := s.Client.GetImage(ctx, s.Host+"/"+repo+"@"+dgst.String())
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !s.Unpack {
		return true, nil
	}
	return image.IsUnpacked(ctx, s.Snapshotter)
}
