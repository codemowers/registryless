package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type Authorizer struct {
	Vault         *Vault
	Core          corev1.CoreV1Interface
	Authorization authzclient.AuthorizationV1Interface
	Legacy        auth.Keys
	work          chan struct{}
	mu            sync.Mutex
	verified      map[[32]byte]time.Time
}

func NewAuthorizer(v *Vault, c corev1.CoreV1Interface, a authzclient.AuthorizationV1Interface, legacy auth.Keys) *Authorizer {
	return &Authorizer{Vault: v, Core: c, Authorization: a, Legacy: legacy, work: make(chan struct{}, 2), verified: map[[32]byte]time.Time{}}
}

func (a *Authorizer) Check(ctx context.Context, user, password, namespace string, write bool) (bool, error) {
	if !strings.HasPrefix(user, "u-") {
		if a.Legacy == nil || (namespace != "" && namespace != user) {
			return false, nil
		}
		roles := []string{"push"}
		if !write {
			roles = append(roles, "pull")
		}
		for _, role := range roles {
			key, err := a.Legacy.Key(ctx, user, role)
			if err == nil && auth.Equal(key, password) {
				return true, nil
			}
		}
		return false, nil
	}
	if len(user) != 34 {
		return false, nil
	}
	entry, err := a.Vault.Lookup(ctx, user)
	if err != nil {
		return false, err
	}
	if entry.Hash == "" || time.Now().After(entry.Expires) || len(password) > 256 {
		return false, nil
	}
	cacheKey := sha256.Sum256([]byte(user + "\x00" + entry.Hash + "\x00" + password))
	a.mu.Lock()
	expires, cached := a.verified[cacheKey]
	a.mu.Unlock()
	if !cached || time.Now().After(expires) {
		select {
		case a.work <- struct{}{}:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		valid := verifyPassword(entry.Hash, password)
		<-a.work
		if !valid {
			return false, nil
		}
		a.mu.Lock()
		if len(a.verified) >= 1024 {
			clear(a.verified)
		}
		a.verified[cacheKey] = time.Now().Add(time.Minute)
		a.mu.Unlock()
	}
	if namespace == "" {
		return true, nil
	}
	ns, err := a.Core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if ns.DeletionTimestamp != nil {
		return false, nil
	}
	attributes := &authzv1.ResourceAttributes{Namespace: namespace, Verb: "get", Group: "", Resource: "pods"}
	if write {
		attributes.Verb = "create"
		attributes.Group = "apps"
		attributes.Resource = "deployments"
	}
	review, err := a.Authorization.SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: entry.Principal.Username, Groups: entry.Principal.Groups, ResourceAttributes: attributes}}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("namespace authorization review: %w", err)
	}
	return review.Status.Allowed, nil
}
