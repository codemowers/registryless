// Package auth checks credentials in the image repository's target namespace.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/typed/core/v1"
)

type Keys interface {
	Key(context.Context, string, string) ([]byte, error)
}

type entry struct {
	key     []byte
	expires time.Time
}
type Secrets struct {
	Client v1.CoreV1Interface
	mu     sync.Mutex
	cache  map[string]entry
}

func (s *Secrets) Key(ctx context.Context, namespace, role string) ([]byte, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("invalid namespace")
	}
	if role != "push" && role != "pull" {
		return nil, fmt.Errorf("invalid credential role")
	}
	cacheKey := namespace + "/" + role
	s.mu.Lock()
	cached, ok := s.cache[cacheKey]
	s.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.key, nil
	}
	secret, err := s.Client.Secrets(namespace).Get(ctx, "registryless-"+role, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("lookup namespace credential: %w", err)
	}
	key := secret.Data["password"]
	if len(key) < 32 {
		return nil, fmt.Errorf("namespace password must contain at least 32 bytes")
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]entry)
	}
	// Bound memory even when authenticated namespaces churn.
	if len(s.cache) >= 1024 {
		clear(s.cache)
	}
	s.cache[cacheKey] = entry{key, time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return key, nil
}

func Equal(key []byte, supplied string) bool {
	a, b := sha256.Sum256(key), sha256.Sum256([]byte(supplied))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// MAC uses a domain prefix so wire messages cannot be reused as HTTP tickets.
func MAC(key []byte, domain string, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain + "\x00"))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
func Verify(key []byte, domain string, data []byte, signature string) bool {
	a, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	b, _ := hex.DecodeString(MAC(key, domain, data))
	return hmac.Equal(a, b)
}
