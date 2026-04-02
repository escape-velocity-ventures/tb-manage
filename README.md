# tb-manage

Infrastructure agent that gives TinkerBelle eyes on every machine. One binary — scans your host, reports to the SaaS, proxies SSH sessions, and remediates workloads.

Co-distributed with [tb-node](https://github.com/escape-velocity-ventures/tb-node) (the VM hypervisor). When you install tb-node, tb-manage comes with it. One install, two capabilities: tb-node creates VMs, tb-manage discovers and manages everything.

## Two Modes, One Binary

tb-manage runs in two modes depending on where it's deployed:

```
Bare metal Mac (plato)
├── tb-manage (host mode — launchd/systemd service)
│     ├── Scans bare metal: CPU, GPU, memory, storage, networking
│     ├── Connects to TinkerBelle SaaS (outbound HTTPS only)
│     ├── Proxies SSH sessions (operator → SaaS → tb-manage → shell)
│     ├── Future: VNC/RDP proxy to desktop
│     ├── Can reach into VMs (VZ shared directories, VM filesystem)
│     └── Reports host + VM inventory to SaaS
│
└── VZ VM (plato-k3s)
      └── tb-manage (cluster mode — DaemonSet)
            ├── Scans k8s resources: pods, services, PVCs, Flux, etc.
            ├── Remediates: pod delete, scale, drain, restart
            ├── Manages VM-internal config (k3s, kubelet, etc.)
            └── Reports cluster state to SaaS
```

**Host mode** runs on the physical machine. It sees hardware, networking, and VMs. It's the SSH endpoint that operators connect through. Co-installed with tb-node as a launchd (macOS) or systemd (Linux) service.

**Cluster mode** runs inside the k8s cluster as a DaemonSet. It sees Kubernetes resources, can remediate workloads, and manages node-level configuration via hostPath mounts. Deployed via GitOps (Flux Kustomization).

Both modes report to the same SaaS control plane. Both use the same identity model.

## Quick Start

### Host Mode (Bare Metal / VM)

```bash
# Install (co-installed with tb-node)
curl -fsSL https://get.tinkerbelle.io/discover | sh

# Configure
sudo tb-manage install \
  --token <agent-token> \
  --url https://gateway.escape-velocity-ventures.org

# This creates:
#   /etc/tb-manage/config.yaml
#   /etc/systemd/system/tb-manage.service (Linux)
#   ~/Library/LaunchDaemons/io.tinkerbelle.manage.plist (macOS)

# Verify
tb-manage status
```

### Cluster Mode (DaemonSet)

Deployed via GitOps. The DaemonSet runs on every node:

```yaml
# TinkerBelle-config/environments/base/infrastructure/tb-manage-terminal.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: tb-manage-terminal
  namespace: infrastructure
spec:
  selector:
    matchLabels:
      app: tb-manage-terminal
  template:
    spec:
      serviceAccountName: tb-manage-terminal
      containers:
        - name: tb-manage-terminal
          image: git.escape-velocity-ventures.org/.../tb-manage:0.10.0
          args:
            - daemon
            - --permissions=terminal
            - --gateway=wss://gateway.escape-velocity-ventures.org/agent/ws
            - --skip-upload
```

### One-Shot Scan

```bash
# Scan and print results (no SaaS connection)
tb-manage scan --profile full --format json

# Scan and upload to SaaS
tb-manage scan --profile standard --token <agent-token>
```

## What It Scans

### Scanner Profiles

| Profile | What's Included | Use Case |
|---------|----------------|----------|
| `minimal` | OS, CPU, memory, architecture | Registration, heartbeat |
| `standard` | + storage, networking, containers, services | Regular inventory |
| `full` | + GPU, IPMI/BMC, SMART, k8s membership | Deep discovery |
| `custom` | User-defined scanner list | Targeted scans |

### Scanners

| Scanner | Data Collected |
|---------|----------------|
| `system` | OS, kernel, CPU, memory, architecture, uptime |
| `storage` | Block devices, partitions, mount points, filesystem types |
| `disk` | Disk usage (df), SMART health |
| `network` | Interfaces, IPs, routes, DNS, listening ports |
| `containers` | Docker/Podman containers, images, volumes |
| `services` | systemd units, listening services |
| `k8s` | kubelet version, cluster membership, node status |
| `capabilities` | GPU (NVIDIA/AMD/Apple), IPMI/BMC, hardware topology |
| `compliance` | CIS benchmarks, security posture |
| `topology` | NUMA, CPU topology, memory channels |

## SSH Session Proxying

tb-manage in host mode acts as the SSH endpoint for remote operator access. Sessions are proxied through the SaaS:

```
Operator (laptop)
  └── ssh plato.tb
        └── cloudflared tunnel → SaaS gateway
              └── WebSocket → tb-manage (on plato)
                    └── shell session (via exec proxy)
```

Authentication uses SSH CA certificates — short-lived, per-session, attributed to a specific operator and bead:

```bash
# Operator authenticates
tb auth login

# SSH cert is minted with:
#   Principal: operator
#   Key ID: agent-benjamin:bead-abc123
#   TTL: 8h

# Connect to any tb-manage host
ssh plato.tb
```

No SSH keys on disk. No authorized_keys management. The cert expires by construction.

## Identity Model

tb-manage uses a per-actor, per-session identity model designed for both humans and AI agents:

| Property | Traditional RBAC | tb-manage |
|----------|-----------------|-----------|
| Granularity | Per-role (shared) | Per-session (unique) |
| Lifetime | Until revoked | Expires by construction (TTL) |
| Attribution | "service-account X did Y" | "agent:oncall-bot:bead-abc123 did Y" |
| Revocation | Delete binding | Wait for TTL |
| Audit | k8s audit log | SSH cert + k8s audit + SaaS log |

Four actor types, one identity model:

| Actor | Auth Method | Default Scope |
|-------|------------|---------------|
| Human operator | Google OIDC → SSH CA cert | 8h, observer tier |
| Oncall bot | Service token → SSH CA cert | 1h, operator tier |
| Sprint agent | Workload identity → SSH CA cert | 30m, scoped to bead |
| Customer AI | API key → SSH CA cert | Per-session, namespace-scoped |

## Remediation (Cluster Mode)

In cluster mode, tb-manage can remediate workloads via the command channel:

| Action | Command | Blast Radius |
|--------|---------|--------------|
| Delete pod | `tb manage pod delete <name>` | Single pod (replica set recreates) |
| Force delete | `tb manage pod delete <name> --force` | Single pod, no grace period |
| Scale | `tb manage scale deploy/<name> --replicas=3` | Single deployment |
| Restart | `tb manage rollout restart deploy/<name>` | Rolling restart |
| Drain node | `tb manage drain <node>` | All pods on node (with PDB respect) |
| Cordon | `tb manage cordon <node>` | No new pods scheduled |

All actions require appropriate tier escalation and are logged to the audit trail.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  tb-manage                                                   │
│                                                               │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
│  │ Scanner │  │ SSH Proxy│  │ Remediate │  │ Command    │  │
│  │         │  │          │  │           │  │ Channel    │  │
│  │ system  │  │ exec     │  │ k8s API   │  │ polls SaaS │  │
│  │ storage │  │ proxy    │  │ mutations │  │ for tasks  │  │
│  │ network │  │ session  │  │           │  │            │  │
│  │ k8s     │  │ mgmt     │  │           │  │            │  │
│  │ gpu     │  │          │  │           │  │            │  │
│  └────┬────┘  └────┬─────┘  └─────┬─────┘  └──────┬─────┘  │
│       │            │              │               │          │
│       └────────────┴──────────────┴───────────────┘          │
│                            │                                  │
│                  outbound HTTPS / WSS only                    │
└────────────────────────────┼──────────────────────────────────┘
                             ▼
                    TinkerBelle SaaS
                    (gateway.escape-velocity-ventures.org)
```

## Relationship to tb-node

tb-node and tb-manage are co-distributed but serve different purposes:

| | tb-node | tb-manage |
|---|---------|-----------|
| **Purpose** | VM hypervisor | Discovery + management agent |
| **Creates** | VMs (via VZ Framework / Hyper-V) | Nothing — discovers what exists |
| **Manages** | VM lifecycle (start, stop, resize) | Host + VM + cluster state |
| **Talks to** | Local only | SaaS (outbound HTTPS/WSS) |
| **Runs as** | CLI + launchd/systemd | launchd/systemd + k8s DaemonSet |
| **Scope** | Bare metal host only | Host + VM interior + k8s cluster |

The install flow:
```
tb-node install
  ├── Installs tb-node binary (VM hypervisor)
  ├── Installs tb-manage binary (agent)
  ├── Registers with SaaS (tb-manage --token)
  └── Machine is now visible to TinkerBelle
```

## CLI Reference

```bash
# Daemon mode (production)
tb-manage daemon [--permissions=terminal|scan|full]
                 [--gateway=wss://...]
                 [--skip-upload]

# Scanning
tb-manage scan [--profile=minimal|standard|full|custom]
               [--format=json|table]
               [--token=<agent-token>]

# Installation
tb-manage install [--token=<agent-token>] [--url=<gateway-url>]
tb-manage uninstall

# Node operations
tb-manage status          # Show agent status
tb-manage check           # Health check
tb-manage version         # Show version
tb-manage register        # Register with SaaS

# Networking
tb-manage net [scan|interfaces|routes]

# Power management
tb-manage power [status|suspend|wake]

# Topology
tb-manage topology        # Show hardware topology

# IoT
tb-manage iot [scan|devices]
```

## Configuration

```yaml
# /etc/tb-manage/config.yaml
url: https://gateway.escape-velocity-ventures.org
token: <agent-token>
profile: standard
scan_interval: 300  # seconds
identity: plato     # node identity
permissions: terminal,scan
```

## Building

```bash
make build    # → ./tb-manage binary
make test     # Run tests
make lint     # go vet
```

## Security

- **Outbound only** — no inbound ports, no listening sockets (except SSH proxy via WSS)
- **Token-based auth** — agent token scoped to SaaS project
- **SSH CA certs** — short-lived, per-session, operator-attributed
- **Minimal RBAC** — cluster mode SA has only the permissions it needs
- **No secrets on disk** — tokens in config.yaml, SSH certs expire by construction
- See `SECURITY-AUDIT-2026-02-27.md` for the full security review

## License

Proprietary — Escape Velocity Ventures Inc.
