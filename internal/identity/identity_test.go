package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func testVault(t *testing.T) (*Vault, *fake.Clientset) {
	t.Helper()
	c := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "registryless-auth", Namespace: "registry"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other"}})
	v := &Vault{Client: c.CoreV1(), Namespace: "registry", Name: "registryless-auth"}
	if err := v.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return v, c
}

func TestRotationInvalidatesCachedPasswordAndRechecksRBAC(t *testing.T) {
	v, c := testVault(t)
	p := Principal{Issuer: "https://issuer.example/", Subject: "alice", Username: "https://issuer.example/#alice", Groups: []string{"developers"}}
	granted := true
	c.PrependReactor("create", "subjectaccessreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		r := action.(clienttesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		if r.Spec.User != p.Username || len(r.Spec.Groups) != 1 {
			t.Fatal("incorrect identity sent to Kubernetes")
		}
		r.Status.Allowed = granted && r.Spec.ResourceAttributes.Namespace == "demo"
		return true, r, nil
	})
	a := NewAuthorizer(v, c.CoreV1(), c.AuthorizationV1(), nil)
	first, err := v.Rotate(context.Background(), p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	check := func(password, namespace string, want bool) {
		t.Helper()
		ok, err := a.Check(context.Background(), p.DockerUsername(), password, namespace, true)
		if err != nil || ok != want {
			t.Fatalf("allowed=%v err=%v want=%v", ok, err, want)
		}
	}
	check(first, "demo", true)
	check(first, "other", false)
	check(first, "absent", false)
	granted = false
	check(first, "demo", false)
	granted = true
	second, err := v.Rotate(context.Background(), p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	check(first, "demo", false)
	check(second, "demo", true)
	s, err := c.CoreV1().Secrets("registry").Get(context.Background(), v.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range s.Data {
		if strings.Contains(string(value), first) || strings.Contains(string(value), second) {
			t.Fatal("plaintext password stored")
		}
	}
	entry, err := v.Lookup(context.Background(), p.DockerUsername())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(entry.Hash, passwordPrefix) {
		t.Fatal("not Argon2id")
	}
	for _, action := range c.Actions() {
		if action.GetResource().Resource == "secrets" && action.GetVerb() == "create" {
			t.Fatal("runtime unexpectedly needs Secret create permission")
		}
	}
	other := &Vault{Client: c.CoreV1(), Namespace: "registry", Name: v.Name}
	if err := other.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if string(other.SessionKey) != string(v.SessionKey) {
		t.Fatal("another replica replaced shared keys")
	}
}

func TestOIDCPKCECallbackAndCredentialPage(t *testing.T) {
	v, _ := testVault(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	var issuer, challenge, nonce string
	wrongNonce := false
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(rw).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(rw http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(rw).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			t.Error("PKCE verifier did not match challenge")
			rw.WriteHeader(400)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "client" || password != "secret" {
			t.Error("client authentication missing")
			rw.WriteHeader(401)
			return
		}
		n := nonce
		if wrongNonce {
			n = "wrong"
		}
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "alice", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": n, "name": "Alice", "groups": []string{"developers"}})
		object, err := signer.Sign(claims)
		if err != nil {
			t.Error(err)
			rw.WriteHeader(500)
			return
		}
		token, err := object.CompactSerialize()
		if err != nil {
			t.Error(err)
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "test-access-token", "token_type": "Bearer", "id_token": token})
	})
	provider := httptest.NewTLSServer(mux)
	defer provider.Close()
	issuer = provider.URL
	ctx := oidc.ClientContext(context.Background(), provider.Client())
	w, err := NewWeb(ctx, v, "https://registry.example", issuer, "client", "secret", "sub", issuer+"#", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	guest := httptest.NewRecorder()
	w.ServeHTTP(guest, httptest.NewRequest("GET", "https://registry.example/", nil))
	login := httptest.NewRecorder()
	w.ServeHTTP(login, httptest.NewRequest("GET", "https://registry.example/auth/login", nil))
	if login.Code != 302 {
		t.Fatal(login.Code)
	}
	u, _ := url.Parse(login.Header().Get("Location"))
	q := u.Query()
	challenge = q.Get("code_challenge")
	nonce = q.Get("nonce")
	if challenge == "" || q.Get("code_challenge_method") != "S256" || nonce == "" {
		t.Fatal("PKCE or nonce missing")
	}
	loginCookie := login.Result().Cookies()[0]
	if !loginCookie.Secure || !loginCookie.HttpOnly {
		t.Fatal("insecure login cookie")
	}
	callback := func(state string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://registry.example/auth/callback?code=code&state="+url.QueryEscape(state), nil)
		r.AddCookie(loginCookie)
		rw := httptest.NewRecorder()
		w.ServeHTTP(rw, r)
		return rw
	}
	if rw := callback("tampered"); rw.Code != 400 {
		t.Fatal("accepted wrong OAuth state")
	}
	wrongNonce = true
	if rw := callback(q.Get("state")); rw.Code != 401 {
		t.Fatal("accepted wrong OIDC nonce", rw.Code)
	}
	wrongNonce = false
	result := callback(q.Get("state"))
	if result.Code != 303 {
		t.Fatal(result.Code, result.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == "__Host-registryless-session" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("missing session cookie")
	}
	c, err := w.open(session.Value, "session")
	if err != nil {
		t.Fatal(err)
	}
	if c.Principal.Username != issuer+"#alice" {
		t.Fatal("incorrect Kubernetes username")
	}
	lifetime := "6mo"
	reset := func(csrf, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://registry.example/credentials/reset", strings.NewReader(url.Values{"csrf": {csrf}, "lifetime": {lifetime}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(session)
		rw := httptest.NewRecorder()
		w.ServeHTTP(rw, r)
		return rw
	}
	if rw := reset("wrong", "https://registry.example"); rw.Code != 403 {
		t.Fatal("accepted forged reset")
	}
	for _, origin := range []string{"null", "https://attacker.example"} {
		if rw := reset(c.CSRF, origin); rw.Code != 403 {
			t.Fatalf("accepted reset from origin %q", origin)
		}
	}
	lifetime = "forever"
	if rw := reset(c.CSRF, "https://registry.example"); rw.Code != 400 {
		t.Fatal("accepted unsupported credential lifetime")
	}
	lifetime = "6mo"
	resetResult := reset(c.CSRF, "https://registry.example")
	if resetResult.Code != 200 || !strings.Contains(resetResult.Body.String(), "docker login") || !strings.Contains(resetResult.Body.String(), "--password-stdin") {
		t.Fatal("login snippet missing", resetResult.Code)
	}
	if resetResult.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential page can be cached")
	}
	entry, err := v.Lookup(context.Background(), c.Principal.DockerUsername())
	if err != nil || entry.Hash == "" {
		t.Fatal("credential not stored", err)
	}
	if delta := time.Until(entry.Expires) - time.Now().AddDate(0, 6, 0).Sub(time.Now()); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatal("selected expiry was not persisted")
	}
	get := httptest.NewRequest("GET", "https://registry.example/", nil)
	get.AddCookie(session)
	rw := httptest.NewRecorder()
	w.ServeHTTP(rw, get)
	if strings.Contains(rw.Body.String(), "--password-stdin") {
		t.Fatal("GET redisplayed one-time credential")
	}
	if got := rw.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("credential form must preserve its same-origin POST Origin: got policy %q", got)
	}
	for _, option := range lifetimeOptions {
		if !strings.Contains(rw.Body.String(), `value="`+option.Value+`"`) {
			t.Fatalf("expiry choice %q missing from form", option.Value)
		}
	}
	if !strings.Contains(rw.Body.String(), `value="1h" selected`) {
		t.Fatal("configured default expiry not selected")
	}
	for _, body := range []string{guest.Body.String(), resetResult.Body.String(), rw.Body.String()} {
		if !strings.Contains(body, `href="https://github.com/codemowers/registryless"`) || !strings.Contains(body, "<svg") {
			t.Fatal("missing GitHub link or icon")
		}
	}
}
