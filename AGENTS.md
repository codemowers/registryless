# Registryless

Registry API backed exclusively by the host containerd store (`k8s.io`). Runs
as a hostNetwork DaemonSet. No PVC, separate registry storage, image pins, or
unrelated changes to ../kube are part of the first iteration. Deployment beside
zot in registry requires the narrow Registryless admission exception recorded
in ../kube; ordinary Pods in that namespace remain restricted.

## Decisions

- First repository component is the target Kubernetes namespace. Legacy HTTP Basic
  username is that namespace; password is `password` in its `registryless-push`
  Secret. `registryless-pull` supplies a separate read-only credential. GET-only
  RBAC on these exact names. Their existence opts the namespace into access.
- OIDC authorization-code + PKCE browser login generates personal Docker
  passwords. Store only Argon2id hashes in the release's named auth Secret;
  namespaced RBAC permits access to this exact Secret without list/create.
  Kubernetes SubjectAccessReviews authorize namespace reads/writes. Existing
  namespace robot credentials remain enabled by default for Kaniko.
- Personal credential generation offers 1h, 24h, 72h, 1w, 2w, 1mo, 3mo and
  6mo lifetimes. Months use calendar dates. Each generation rotates the hash.
- auth.mode=none disables public push/pull authentication and namespace RBAC;
  OIDC must be disabled in this mode. Internal transfer signatures stay enabled.
  Platform-managed private Ingress TLS is supported independently of auth mode.
  CA trust belongs to platform admission; do not bake a CA bundle into the image.
- Helm supplies REGISTRY_NAMESPACE from .Release.Namespace for auth storage and
  peer discovery. Do not infer the workload's target namespace from the daemon.
- Ingress can select any agent. Upload IDs include the owning host address;
  other agents forward authenticated upload requests to it.
- Multicast uses the host IPv4 NIC selected by its lowest-metric usable default
  route. Explicit interface and advertised IPv4 overrides support multihoming.
- SHA-256 of the normalized OS/architecture/variant selects a group within
  239.192.0.0/14. Full platform is checked as well. TTL defaults to 1.
- A versioned binary header wraps announcements, chunks, and completion packets.
  Announcements are authenticated with a shared release distribution key.
  Data is verified with the announced SHA-256 digest; multicast is plaintext.
  Trusted host network is required. No mTLS.
- Each transfer writes to containerd ingest under an expiring lease. Committed
  blobs remain under an expiring staging lease until an image references them.
  Manifest links use containerd GC labels. Completed images are registered and
  unpacked, without pinning. containerd and kubelet own garbage collection.
- UDP loss/reordering is repaired with authenticated HTTP range downloads from
  the publisher. Optional push.sync waits for current matching-platform agents
  before acknowledging the final manifest. No nodestatd catalogue integration
  or discovery of historical images on late join yet. No image pins.
- Limit concurrent transfers, blob sizes, upload lifetimes, HTTP work, and queue
  depth. Keep secrets out of logs. Fail closed on credential lookup failures.
- Metrics use internal HTTP on the named metrics port. Render a PodMonitor when
  its API exists, selecting this release's Pods by app name and instance labels.

## Development

Environment-specific Helm values (`chart/values.*.yaml`), `skaffold.env` and
promotion scripts stay local and gitignored. Use placeholder hosts in tracked
examples; do not stage infrastructure topology.

`go test ./...`, `go vet ./...`, `go build ./cmd/registryless`.
Integration tests use REGISTRYLESS_TEST_CONTAINERD to target an isolated daemon,
never the host's production containerd. No automatic cluster deployment.
