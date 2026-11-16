package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/distribution"
	"github.com/codemowers/registryless/internal/identity"
	"github.com/codemowers/registryless/internal/metrics"
	"github.com/codemowers/registryless/internal/multicast"
	"github.com/codemowers/registryless/internal/network"
	"github.com/codemowers/registryless/internal/registry"
	"github.com/codemowers/registryless/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/platforms"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/api/resource"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
func integer(key string, fallback int64) (int64, error) {
	v, err := strconv.ParseInt(env(key, strconv.FormatInt(fallback, 10)), 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return v, nil
}

func byteQuantity(key, fallback string) (int64, error) {
	q, err := resource.ParseQuantity(env(key, fallback))
	if err != nil || q.Sign() <= 0 {
		return 0, fmt.Errorf("%s must be a positive byte quantity, such as 10Mi", key)
	}
	value := q.Value()
	if value <= 0 {
		return 0, fmt.Errorf("%s is outside the supported byte range", key)
	}
	return value, nil
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	iface, ip, err := network.Discover(env("MULTICAST_INTERFACE", ""), env("ADVERTISE_IP", ""))
	if err != nil {
		return err
	}
	platform := network.Platform(platforms.DefaultSpec())
	group := network.Group(platform)
	httpPort, err := integer("HTTP_PORT", 5282)
	if err != nil || httpPort > 65535 {
		return fmt.Errorf("invalid HTTP_PORT")
	}
	udpPort, err := integer("MULTICAST_PORT", 5283)
	if err != nil || udpPort > 65535 {
		return fmt.Errorf("invalid MULTICAST_PORT")
	}
	ttl, err := integer("MULTICAST_TTL", 1)
	if err != nil || ttl > 255 {
		return fmt.Errorf("invalid MULTICAST_TTL")
	}
	rate, err := byteQuantity("MULTICAST_BYTES_PER_SECOND", "10Mi")
	if err != nil {
		return err
	}
	maxBlob, err := integer("MAX_BLOB_BYTES", 2<<30)
	if err != nil || maxBlob > 16<<30 {
		return fmt.Errorf("MAX_BLOB_BYTES must be between 1 and 17179869184")
	}
	host := env("REGISTRY_HOST", "")
	if host == "" {
		return fmt.Errorf("REGISTRY_HOST is required (hostname[:port], without scheme)")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if h == "" {
			return fmt.Errorf("invalid REGISTRY_HOST")
		}
	} else if net.ParseIP(host) == nil {
		for _, r := range host {
			if r == '/' || r == ' ' || r == '\n' {
				return fmt.Errorf("invalid REGISTRY_HOST")
			}
		}
	}
	client, err := containerd.New(env("CONTAINERD_ADDRESS", "/run/containerd/containerd.sock"), containerd.WithDefaultNamespace(env("CONTAINERD_NAMESPACE", "k8s.io")))
	if err != nil {
		return err
	}
	defer client.Close()
	checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	serving, err := client.IsServing(checkCtx)
	checkCancel()
	if err != nil || !serving {
		return fmt.Errorf("containerd is not serving: %v", err)
	}
	var cfg *rest.Config
	if path := env("KUBECONFIG", ""); path != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", path)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return err
	}
	cfg.Timeout = 5 * time.Second
	kube, err := corev1.NewForConfig(cfg)
	if err != nil {
		return err
	}
	namespace := env("REGISTRY_NAMESPACE", "registry")
	authMode := env("AUTH_MODE", "rbac")
	if authMode != "rbac" && authMode != "none" {
		return fmt.Errorf("AUTH_MODE must be rbac or none")
	}
	vault := &identity.Vault{Client: kube, Namespace: namespace, Name: env("AUTH_SECRET_NAME", "registryless-auth")}
	if err := vault.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize named credential Secret: %w", err)
	}
	var keys auth.Keys = vault
	legacyEnabled, err := strconv.ParseBool(env("LEGACY_NAMESPACE_AUTH", "true"))
	if err != nil {
		return err
	}
	var legacy auth.Keys
	if legacyEnabled {
		legacy = &auth.Secrets{Client: kube}
	}
	authz, err := authzclient.NewForConfig(cfg)
	if err != nil {
		return err
	}
	credentials := identity.NewAuthorizer(vault, kube, authz, legacy)
	unpack, err := strconv.ParseBool(env("UNPACK_IMAGES", "true"))
	if err != nil {
		return err
	}
	s := &store.Store{Client: client, Host: host, Platform: platform, Snapshotter: env("SNAPSHOTTER", ""), Unpack: unpack, TTL: time.Hour}
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	m := metrics.New(reg)
	address := net.JoinHostPort(ip.String(), strconv.FormatInt(httpPort, 10))
	agent := &multicast.Agent{Store: s, Keys: keys, Metrics: m, Log: log, Address: address, MaxBlob: maxBlob, BytesPerSecond: rate, ReorderWindow: 2 * time.Second, Timeout: 10 * time.Minute}
	if err := agent.Open(ctx, iface, group, int(udpPort), int(ttl)); err != nil {
		return err
	}
	proxy := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 16, ResponseHeaderTimeout: 10 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pushSync, err := strconv.ParseBool(env("PUSH_SYNC", "false"))
	if err != nil {
		return err
	}
	syncTimeout, err := time.ParseDuration(env("PUSH_SYNC_TIMEOUT", "5m"))
	if err != nil || syncTimeout <= 0 || syncTimeout > 30*time.Minute {
		return fmt.Errorf("PUSH_SYNC_TIMEOUT must be positive and at most 30m")
	}
	barrier := &distribution.Barrier{Core: kube, Keys: keys, Namespace: namespace, Selector: env("AGENT_SELECTOR", "app.kubernetes.io/name=registryless"), Platform: platform, Port: int(httpPort), Timeout: syncTimeout}
	handler := &registry.Server{Store: s, Keys: keys, Publisher: agent, Authenticator: credentials, Barrier: barrier, PushSync: pushSync, Address: address, MaxBlob: maxBlob, Log: log, Proxy: proxy, Slots: make(chan struct{}, 128)}
	handler.Authless = authMode == "none"
	routes := http.NewServeMux()
	routes.Handle("/v2/", handler)
	routes.Handle("/v2", handler)
	routes.Handle("/internal/", handler)
	oidcEnabled, err := strconv.ParseBool(env("OIDC_ENABLED", "false"))
	if err != nil {
		return err
	}
	if oidcEnabled {
		if authMode == "none" {
			return fmt.Errorf("OIDC_ENABLED must be false when AUTH_MODE is none")
		}
		issuer := env("OIDC_ISSUER", "")
		id := env("OIDC_CLIENT_ID", "")
		secret := env("OIDC_CLIENT_SECRET", "")
		if issuer == "" || id == "" || secret == "" {
			return fmt.Errorf("OIDC issuer, client ID and secret are required")
		}
		ttl, err := time.ParseDuration(env("DOCKER_PASSWORD_TTL", "24h"))
		if err != nil || ttl <= 0 {
			return fmt.Errorf("DOCKER_PASSWORD_TTL must be positive")
		}
		claim := env("OIDC_USERNAME_CLAIM", "sub")
		prefix := ""
		if claim == "sub" {
			prefix = issuer + "#"
		}
		discoveryCtx, discoveryCancel := context.WithTimeout(ctx, 20*time.Second)
		web, err := identity.NewWeb(discoveryCtx, vault, "https://"+host, issuer, id, secret, claim, env("OIDC_USERNAME_PREFIX", prefix), env("OIDC_GROUPS_PREFIX", ""), ttl)
		discoveryCancel()
		if err != nil {
			return err
		}
		routes.Handle("/", web)
	} else {
		routes.Handle("/", registry.Home(host, authMode == "none"))
	}
	server := &http.Server{Addr: net.JoinHostPort("", strconv.FormatInt(httpPort, 10)), Handler: routes, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10*time.Minute + syncTimeout, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		ok, err := client.IsServing(c)
		if err != nil || !ok {
			http.Error(w, "containerd unavailable", 503)
			return
		}
		w.WriteHeader(200)
	})
	admin := &http.Server{Addr: env("METRICS_ADDRESS", ":5284"), Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	errs := make(chan error, 3)
	go func() { errs <- agent.Run() }()
	go func() { errs <- server.ListenAndServe() }()
	go func() { errs <- admin.ListenAndServe() }()
	log.Info("registryless started", "interface", iface.Name, "address", address, "platform", platform, "multicast_group", group.String(), "multicast_port", udpPort)
	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}
	cancel()
	if err := agent.Close(); err != nil {
		log.Warn("close multicast socket", "error", err)
	}
	shutdown, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	for _, srv := range []*http.Server{server, admin} {
		if err := srv.Shutdown(shutdown); err != nil {
			log.Warn("HTTP shutdown", "error", err)
		}
	}
	if result == http.ErrServerClosed {
		return nil
	}
	return result
}

func main() {
	if err := run(); err != nil {
		slog.Error("registryless stopped", "error", err)
		os.Exit(1)
	}
}
