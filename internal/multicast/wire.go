// Package multicast distributes content over host IPv4 multicast.
package multicast

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/registry"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	HeaderSize      = 32
	ChunkSize       = 1200
	Announce   byte = 1
	Data       byte = 2
	Done       byte = 3
)

type ID [16]byte

func NewID() ID {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Header: RGLS | version:u8 | kind:u8 | reserved:u16 | ID:128 | offset:u64.
// All integers are big endian. Payload is <=1200 bytes; datagram <=1232 bytes.
func Encode(kind byte, id ID, offset uint64, payload []byte) []byte {
	b := make([]byte, HeaderSize+len(payload))
	copy(b, "RGLS")
	b[4] = 1
	b[5] = kind
	copy(b[8:24], id[:])
	binary.BigEndian.PutUint64(b[24:32], offset)
	copy(b[32:], payload)
	return b
}
func Decode(b []byte) (byte, ID, uint64, []byte, error) {
	var id ID
	if len(b) < HeaderSize || len(b) > HeaderSize+ChunkSize || string(b[:4]) != "RGLS" || b[4] != 1 || b[6] != 0 || b[7] != 0 || b[5] < Announce || b[5] > Done {
		return 0, id, 0, nil, fmt.Errorf("invalid wire header")
	}
	copy(id[:], b[8:24])
	return b[5], id, binary.BigEndian.Uint64(b[24:32]), b[32:], nil
}

type Announcement struct {
	ID         string             `json:"id"`
	Platform   string             `json:"platform"`
	Repository string             `json:"repository"`
	Reference  string             `json:"reference,omitempty"`
	Descriptor ocispec.Descriptor `json:"descriptor"`
	Source     string             `json:"source"`
	Expires    int64              `json:"expires"`
}
type signed struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

func sign(a Announcement, key []byte) ([]byte, error) {
	body, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(signed{body, auth.MAC(key, "announcement", body)})
	if len(b) > ChunkSize {
		return nil, fmt.Errorf("announcement too large")
	}
	return b, err
}
func verify(b []byte, key []byte, id ID, platform string, source net.IP, maxBlob int64) (Announcement, error) {
	var s signed
	var a Announcement
	if err := json.Unmarshal(b, &s); err != nil {
		return a, err
	}
	if !auth.Verify(key, "announcement", s.Body, s.Signature) {
		return a, fmt.Errorf("invalid announcement signature")
	}
	if err := json.Unmarshal(s.Body, &a); err != nil {
		return a, err
	}
	host, port, err := net.SplitHostPort(a.Source)
	if err != nil || port == "" || !net.ParseIP(host).Equal(source) {
		return a, fmt.Errorf("invalid source address")
	}
	if a.ID != id.String() || a.Platform != platform || !registry.ValidRepo(a.Repository) || a.Expires < time.Now().Unix() || a.Expires > time.Now().Add(time.Hour).Unix() || a.Descriptor.Size < 0 || a.Descriptor.Size > maxBlob || a.Descriptor.Digest.Validate() != nil || a.Descriptor.Digest.Algorithm() != digest.SHA256 {
		return a, fmt.Errorf("invalid announcement identity, lifetime or descriptor")
	}
	return a, nil
}
