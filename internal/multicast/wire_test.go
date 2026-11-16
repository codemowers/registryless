package multicast

import (
	"net"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestWireAndPlatformValidation(t *testing.T) {
	id := NewID()
	key := []byte("01234567890123456789012345678901")
	meta := Announcement{ID: id.String(), Platform: "linux/arm/v7", Repository: "project/api", Descriptor: ocispec.Descriptor{Digest: digest.FromString("hello"), Size: 5}, Source: "10.0.0.1:5282", Expires: time.Now().Add(time.Minute).Unix()}
	b, err := sign(meta, key)
	if err != nil {
		t.Fatal(err)
	}
	wire := Encode(Announce, id, 0, b)
	kind, gotID, offset, payload, err := Decode(wire)
	if err != nil || kind != Announce || gotID != id || offset != 0 {
		t.Fatal("header round trip failed", err)
	}
	if _, err := verify(payload, key, id, "linux/arm/v7", net.ParseIP("10.0.0.1"), 100); err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/arm/v6", "linux/arm64", "windows/arm/v7"} {
		if _, err := verify(payload, key, id, platform, net.ParseIP("10.0.0.1"), 100); err == nil {
			t.Fatalf("accepted foreign platform %s", platform)
		}
	}
	if _, err := verify(payload, []byte("wrong key"), id, meta.Platform, net.ParseIP("10.0.0.1"), 100); err == nil {
		t.Fatal("accepted forged announcement")
	}
	if _, err := verify(payload, key, id, meta.Platform, net.ParseIP("10.0.0.2"), 100); err == nil {
		t.Fatal("accepted wrong sender")
	}
	wire[4] = 2
	if _, _, _, _, err := Decode(wire); err == nil {
		t.Fatal("accepted unsupported wire version")
	}
	for n := 0; n < HeaderSize; n++ {
		if _, _, _, _, err := Decode(wire[:n]); err == nil {
			t.Fatal("accepted truncated header")
		}
	}
}
