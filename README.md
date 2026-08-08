# basis

Cluster-wide Flux Kustomization content for the kCluster base stack: operator
installs (cert-manager, crossplane, kyverno, cnpg, observability) and platform
resources (Crossplane providers, Kyverno cleanup policies).

## Out of scope: kube-vip

kube-vip configuration is intentionally **out of scope** for this repo. It is
owned entirely by `simplesalt/oci`'s node bootstrap (`cluster/bootstrap.sh`),
which reads the `vip` field from the USB `config.yaml` and writes the
kube-vip RBAC and DaemonSet manifests directly to
`/var/lib/rancher/k3s/server/manifests/` on each control-plane node at boot,
before k3s and Flux even start.

Do not re-add kube-vip manifests or a Flux HelmRelease/Kustomization for it
here -- that would create a second, conflicting source of truth for the
cluster's HA control-plane VIP.
