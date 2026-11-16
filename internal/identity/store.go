// Package identity provides browser OIDC sessions and per-user Docker credentials.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

type Principal struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Groups      []string `json:"groups,omitempty"`
}

func (p Principal) DockerUsername() string {
	h := sha256.Sum256([]byte(p.Issuer + "\x00" + p.Subject))
	return "u-" + hex.EncodeToString(h[:16])
}

type Credential struct {
	Principal Principal `json:"principal"`
	Hash      string    `json:"hash"`
	Expires   time.Time `json:"expires"`
}

type Vault struct {
	Client                      corev1.CoreV1Interface
	Namespace, Name             string
	SessionKey, DistributionKey []byte
}

// The chart creates this one named Secret. Runtime RBAC never needs create or
// list permission on Secrets. Only these two random keys and password hashes
// are stored; plaintext generated Docker passwords are returned once.
func (v *Vault) Initialize(ctx context.Context) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		s, err := v.Client.Secrets(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		changed := false
		for _, key := range []string{"session-key", "distribution-key"} {
			if len(s.Data[key]) == 0 {
				s.Data[key] = []byte(randomToken())
				changed = true
			}
		}
		if changed {
			s, err = v.Client.Secrets(v.Namespace).Update(ctx, s, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		if len(s.Data["session-key"]) < 32 || len(s.Data["distribution-key"]) < 32 {
			return fmt.Errorf("invalid identity Secret keys")
		}
		v.SessionKey = append([]byte(nil), s.Data["session-key"]...)
		v.DistributionKey = append([]byte(nil), s.Data["distribution-key"]...)
		return nil
	})
}

func (v *Vault) Key(context.Context, string, string) ([]byte, error) { return v.DistributionKey, nil }

func (v *Vault) Lookup(ctx context.Context, username string) (Credential, error) {
	var entry Credential
	if len(username) != 34 || username[:2] != "u-" {
		return entry, fmt.Errorf("invalid Docker username")
	}
	s, err := v.Client.Secrets(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
	if err != nil {
		return entry, err
	}
	data, ok := s.Data[username]
	if !ok {
		return entry, nil
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return entry, fmt.Errorf("invalid stored credential")
	}
	if entry.Principal.DockerUsername() != username {
		return Credential{}, fmt.Errorf("credential identity mismatch")
	}
	return entry, nil
}

func (v *Vault) Rotate(ctx context.Context, p Principal, ttl time.Duration) (string, error) {
	password := randomToken()
	entry := Credential{Principal: p, Hash: hashPassword(password), Expires: time.Now().Add(ttl)}
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		s, err := v.Client.Secrets(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data[p.DockerUsername()] = data
		_, err = v.Client.Secrets(v.Namespace).Update(ctx, s, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return "", err
	}
	return password, nil
}
