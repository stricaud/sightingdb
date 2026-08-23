# SightingDB Helm chart

Runs [SightingDB](https://github.com/stricaud/sightingdb) on Kubernetes: one
pod, one volume, and the daemon's whole configuration file rendered from
`values.yaml`.

From the repository root, `make dev` builds the image from the local source,
creates a kind cluster, installs this chart into it and writes a sighting to
prove it works. `make help` lists the rest.

## Installing

    helm install sightingdb ./helm/sightingdb \
      --namespace sightingdb --create-namespace \
      --set image.repository=ghcr.io/you/sightingdb --set image.tag=0.5.5

Then:

    kubectl -n sightingdb port-forward svc/sightingdb 9999:9999
    kubectl -n sightingdb get secret sightingdb-acl -o jsonpath='{.data.admin-key}' | base64 -d

and the management interface is at <http://localhost:9999/_management/>.

`helm test sightingdb -n sightingdb` writes a sighting and reads it back, which
is a better answer to "is it working" than a pod that is merely Running.

## What it creates

| Object | |
| --- | --- |
| StatefulSet | One pod. See [Why one pod](#why-one-pod). |
| Service | The HTTP API and the management interface. |
| Service (headless) | The StatefulSet's governing service. |
| Service (`-dns`) | UDP and TCP, only when `config.dns.enabled`. |
| ConfigMap | `sightingdb.toml` and `log4rs.yml`, rendered from values. |
| Secret (`-acl`) | `acl.toml` and the admin key, rendered from `acl.keys`. |
| PersistentVolumeClaim | The data directory, via a volumeClaimTemplate. |
| Job (`-bootstrap`) | Creates `bootstrap.namespaces` after install and upgrade. |
| Pod (test) | `helm test`: writes a sighting, reads it back, deletes it. |

## Configuration

Everything under `config` is the daemon's configuration file, key for key with
[`etc/sightingdb.toml`](../../etc/sightingdb.toml). A key left null is not
written at all, so the daemon's own default applies — which matters, because it
refuses to start on a key it does not recognise.

Five things are *not* under `config`, because the chart has to decide them and
two places to set one thing is one too many:

| Set by the chart | From | Why |
| --- | --- | --- |
| `daemonize` | always false | The container is the process. |
| `ssl`, `ssl_cert`, `ssl_key` | `tls` | See below. |
| `acl_file` | `persistence` | Rewritten by the interface, so it must be writable. |
| `tiers_file` | `persistence` | The same. |
| `dbdir` | `config.daemon.dbdir` | Defaults to the mounted volume; a path outside it would not survive the pod. |

`configOverride` takes raw TOML and replaces all of it, and
`existingConfigMap` uses a ConfigMap you manage yourself. Both are escape
hatches for something the chart does not model yet.

### Values

| Key | Default | |
| --- | --- | --- |
| `image.repository` | `sightingdb` | |
| `image.tag` | `""` | Defaults to the chart's appVersion. |
| `image.pullPolicy` | `IfNotPresent` | |
| `image.pullSecrets` | `[]` | |
| `service.type` | `ClusterIP` | Also `port`, `nodePort`, `annotations`, `labels`, `clusterIP`, `loadBalancerIP`, `loadBalancerSourceRanges`, `externalTrafficPolicy`. |
| `dnsService.*` | | The same set, for the DNS listener. |
| `ingress.enabled` | `false` | With `className`, `annotations`, `hosts`, `tls`. |
| `persistence.enabled` | `true` | With `size`, `storageClass`, `accessModes`, `annotations`, `existingClaim`. |
| `tls.mode` | `disabled` | `disabled`, `secret` or `selfsigned`. |
| `tls.secretName` | `""` | Required when the mode is `secret`. |
| `acl.keys` | `{}` | The API keys and what each may reach. Empty generates one admin key. |
| `acl.existingSecret` | `""` | A Secret of your own, with `acl.toml` and `admin-key` in it. |
| `acl.overwriteOnStart` | `false` | See [API keys](#api-keys). |
| `bootstrap.namespaces` | `[]` | Namespaces to create after install and upgrade. |
| `bootstrap.timeoutSeconds` | `120` | How long that job waits for the daemon. |
| `logging.level` | `info` | Also `writeLog` and a raw `config`. |
| `probes.*` | enabled | Startup, liveness and readiness, all on `/health`. |
| `resources` | `{}` | |
| `podSecurityContext`, `securityContext` | non-root, read-only root filesystem | |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName` | | Ordinary scheduling controls. |
| `terminationGracePeriodSeconds` | `120` | The database is written out on the way down. |
| `extraArgs`, `extraEnv`, `extraEnvFrom`, `extraVolumes`, `extraVolumeMounts`, `extraInitContainers` | | |
| `config.daemon.*` | | `enabled`, `listen_ip`, `listen_port`, `authenticate`, `post_limit`, `dbdir`, `snapshot_interval`, `compression_level`, `sweep_interval`, `stats_retention`, `shadow_ttl`. |
| `config.storage.*` | | `default_tier`, `warm_idle`, `tiers`. |
| `config.dns.*` | disabled | `zone`, `listen_ip`, `listen_port`, `ttl`, `rate_limit`, `threads`, `shadow`, `namespaces`. |
| `config.zmq.*` | disabled | `endpoint`, `topics`, `format`, `require_to_ids`, `default_namespace`, `ttl`, `reconnect`, `types`. |
| `config.stix.*` | | `identity`, `identity_class`, `default_namespace`, `ttl`, `types`. |
| `configOverride` | `""` | Raw TOML, replacing everything under `config`. |
| `existingConfigMap` | `""` | A ConfigMap of your own. |

## API keys

**Where the key is.** The chart puts it in a Secret named `<release>-acl`, with
two entries: `acl.toml` (the whole file) and `admin-key` (the first key holding
the `admin` grant, on its own):

    kubectl -n sightingdb get secret sightingdb-acl -o jsonpath='{.data.admin-key}' | base64 -d

or `make admin-key` from the repository root.

**Where it comes from.** Leave `acl.keys` empty — the default — and one key with
full access is generated on install and kept across upgrades, by reading the
existing Secret back. Set `acl.keys` and those are the keys, verbatim. A chart
that shipped a known key would install a database anyone who has read the chart
can write to, which is why there is no default key.

**Changing keys after the first install** takes one more step, because the
daemon reads the copy on the volume: the init container leaves that copy alone
so keys made in the interface are not thrown away, and says so in its log when
it differs from the Secret. To make the values authoritative again:

    kubectl -n sightingdb delete secret sightingdb-acl      # only to force a new generated key
    helm upgrade ... --set acl.overwriteOnStart=true

Generation reads the cluster, so it only works when Helm can talk to one.
`helm template`, or `--dry-run` without a server, has nothing to read and mints
a fresh key each time; installing from such a rendering rather than with
`helm install` would give you a different key on every apply. Set `acl.keys`
explicitly if that is how you deploy.

A Secret is base64, not encryption: anyone who can `get secrets` in the
namespace can read the key, as can anyone who can read the release's own Secret.
Treat it accordingly.

**Why a file rather than an environment variable.** The daemon also accepts
`SIGHTINGDB_APIKEY`, and the chart deliberately does not use it: an environment
variable holds one key with unrestricted access, shows up in `kubectl describe
pod`, and is readable from `/proc/<pid>/environ` by anything sharing the
namespace. A mounted file carries every key with its own grants and is seen by
the process that opens it. If you want the variable anyway — a single-key
deployment, say — `extraEnv` will carry it:

    extraEnv:
      - name: SIGHTINGDB_APIKEY
        valueFrom:
          secretKeyRef: { name: my-secret, key: apikey }

`acl.keys` is rendered into a Secret. The management interface rewrites
`acl.toml` when a key is created or revoked, and a mounted Secret is read-only,
so an init container copies it onto the data volume on first start and the
daemon reads that copy.

The consequence is worth being clear about: **keys created in the interface live
on the volume, not in the Secret**, and `helm upgrade` does not touch them. Set
`acl.overwriteOnStart=true` to manage keys purely from values, accepting that
anything created in the interface is replaced at the next restart.

The Secret also carries an `admin-key` entry — the first key holding the `admin`
grant — because the bootstrap job and the chart test need a key without parsing
TOML in a shell. Bringing your own `acl.existingSecret` means putting the same
entry in it.

## Namespaces

A namespace normally comes into being when something is first written to it.
`bootstrap.namespaces` creates them up front, through the management API, as a
post-install and post-upgrade hook, so a deployment starts with the structure
its writers and its ACL prefixes already assume:

    bootstrap:
      namespaces:
        - feeds/misp/ips
        - feeds/misp/domains

Creating one that already exists is a no-op, so upgrades are safe.

## TLS

| `tls.mode` | |
| --- | --- |
| `disabled` | Plain HTTP. The usual arrangement: TLS ends at the ingress, and the pod is reached over the pod network. |
| `secret` | Mounts a `kubernetes.io/tls` Secret named by `tls.secretName` and serves HTTPS from it. |
| `selfsigned` | An init container has the binary write a certificate onto the data volume on first start. For getting going; a client outside the cluster will not trust it. |

The probes follow: they speak HTTPS whenever the pod terminates TLS itself.

## Running unprivileged

The pod runs as uid 10001 with `runAsNonRoot`, a read-only root filesystem and
every capability dropped — the *restricted* Pod Security Standard, which some
clusters enforce. The daemon has no privilege dropping of its own and needs
none; it is started unprivileged instead, which leaves no window in which it is
root. Everything it writes goes to the mounted volume, which `fsGroup` makes
writable.

Binding a port below 1024 is the one thing that needs more, and it is a
capability rather than root:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]

The DNS listener defaults to 5353 with the Service mapping 53 onto it, so that
is usually unnecessary.

## Why one pod

There is deliberately no `replicaCount`. SightingDB holds its data in memory and
snapshots it to one directory. A second replica would be a second, unrelated
database answering half the requests, with its own consensus counts and its own
API keys — and if both mounted the same volume, they would take turns
overwriting each other's snapshots. Scale by giving the pod more memory.

It is a StatefulSet rather than a Deployment for the same reason: a rolling
Deployment would briefly run two pods on one volume.

## Upgrades

`helm upgrade` restarts the pod. The database is written out on the way down —
`terminationGracePeriodSeconds` is 120 to leave room for that on a large
database — and read back on the way up, so a restart costs the time of one
snapshot and one load. Whatever was written since the last snapshot is not lost,
because shutdown takes one.
