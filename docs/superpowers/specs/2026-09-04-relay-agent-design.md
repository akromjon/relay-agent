# relay-agent — read-only stats agent for CHOP relay boxes

**Date:** 2026-09-04
**Status:** design, approved in discussion, pending written review
**Owner:** akyprog
**Repo:** github.com/akromjon/relay-agent

## Problem

CHOP fronts VPN origins with relay boxes (kernel nftables DNAT). When a
relay's IP is blocked on Russian consumer networks, or the relay box dies,
every node behind it goes to 0% connect at once while the origins stay
healthy. Today the only way to see this is a human SSHing to the relay and
reading `nft` counters and packet captures. On 2026-09-04 six candidate
relays were canaried by hand; each verdict rested on one relay-side number
(new flows arriving at the DNAT port: 0 = blocked, dozens = clean) that
nothing on the backend can read.

The backend needs a machine-readable window into each relay so a detector
can combine backend session outcomes with relay-side packet counters and
decide, without a human, whether a relay is blocked, dead, or fine.

## Goal (phase 1)

A single static Go binary on every relay that answers HTTP on demand with
the kernel counters the detector needs. Read-only. No background work. No
change to the datapath. Installable on a bare VPS with one command that also
performs the standard relay prep.

## Non-goals (phase 1)

- Writing or changing nft rules (phase 2 adds `POST /api/rules` to the same
  binary; the read path is designed so phase 2 is additive).
- Any decision logic. The agent reports numbers; the backend decides.
- Packet capture, pcap, sampling, or any per-packet work.
- Historical storage. The agent keeps no state; the backend diffs counters.

## Architecture

```
backend (Laravel, every minute)  --GET /api/stats-->  relay-agent (:8080)
                                                         |  exec nft -j list table ip chop_relay
                                                         |  exec conntrack -L
                                                         |  read /proc/net/dev, /proc/loadavg, /proc/stat,
                                                         |       /proc/meminfo, /proc/sys/net/netfilter/*
                                                         v
                                                       JSON
```

The agent is idle between requests. Each request costs two short `exec`s
(~5 ms and ~10 ms on a 1 vCPU Regxa box) and five `/proc` reads. Nothing
is cached; every response is a fresh read.

### Why exec, not netlink

`/proc/net/nf_conntrack` is compiled out on Ubuntu 24.04 (no procfs
conntrack), and reading nftables/conntrack via netlink from Go pulls in
`google/nftables` + `ti-mo/conntrack` and their transitive deps. Shelling
out to the two CLIs the fleet already has (`nft`, `conntrack-tools`) keeps
the binary dependency-free (stdlib only) and the failure modes obvious.
The install script installs `conntrack` if missing.

## HTTP API

Bind: `0.0.0.0:${RELAY_AGENT_PORT}` (default 8080; relays run nothing else
on 8080). All `/api/*` routes require header `key: <API_TOKEN>`. A wrong or
missing key returns **404** (same convention as `vless-api`: the endpoint
does not reveal itself). Responses are `application/json`.

### `GET /api/health`

```json
{
  "running": true,
  "version": "0.1.0",
  "uptime_s": 12345,
  "iface": "eth0",
  "ip_forward": true,
  "conntrack_max": 262144,
  "nft_table_present": true
}
```

`running` is always true when the process answers; TCP reachability of
this endpoint from the backend is itself a signal (a relay that answers
here but receives no user packets is blocked on the user side, not dead).

### `GET /api/stats`

```json
{
  "ts": 1757000000,
  "iface": "eth0",
  "rules": [
    {"proto": "udp", "port": 2053, "origin": "<origin-ip>", "origin_port": 443,
     "new_flows": 126, "bytes": 54304}
  ],
  "origins": [
    {"origin": "<origin-ip>", "origin_port": 443, "proto": "udp",
     "flows": 6, "replied": 5, "client_ips": 4}
  ],
  "box": {
    "rx_bytes": 4315119032, "tx_bytes": 110235507,
    "rx_packets": 208335, "tx_packets": 65348,
    "rx_drop": 13, "tx_drop": 0,
    "conntrack_count": 6, "conntrack_max": 262144,
    "load1": 0.02, "mem_avail_kb": 690000,
    "cpu_steal_pct": 0.0, "cpu_idle_pct": 99.1
  }
}
```

Field semantics:

- `rules[]` — one entry per `dnat` rule in `table ip chop_relay chain
  prerouting`, parsed from `nft -j`. `new_flows` and `bytes` are the rule's
  `counter` values. **A counter on a nat-hook rule counts only the first
  packet of each flow**, so `new_flows` is a flow count, not throughput.
  Cumulative since the rule was loaded; the backend diffs successive reads.
  Rules without a `counter` expression report `new_flows: null`.
- `origins[]` — grouped from `conntrack -L` entries whose reply tuple
  source is `origin:origin_port`. `flows` = entries, `replied` = entries
  not marked `[UNREPLIED]`, `client_ips` = distinct original-direction
  source addresses. This is the relay→origin leg: `flows > 0, replied = 0`
  means the origin is silent.
- `box` — `/proc/net/dev` for the configured interface (cumulative),
  `/proc/sys/net/netfilter/nf_conntrack_{count,max}`, `/proc/loadavg`,
  `/proc/meminfo` `MemAvailable`, and a **two-sample** `/proc/stat` read
  100 ms apart for `cpu_steal_pct` / `cpu_idle_pct` (the only deliberate
  wait in the agent; it is bounded and only on this endpoint).

Errors: if `nft` fails (table absent) `rules` is `[]` and
`nft_table_present` on health is false; if `conntrack` fails `origins` is
`[]` and `warnings[]` carries the stderr line. A `/proc` read failure is a
500 — that box is broken in a way worth surfacing.

### `GET /api/rules`

The same `rules[]` array as `/api/stats` without counters, plus the
`postrouting` masquerade entries. Read-only in phase 1. Exists so phase 2's
`POST /api/rules` has a matching read side from day one.

## Configuration

`/etc/relay-agent/.env` (systemd `EnvironmentFile`):

| Var | Default | Meaning |
| --- | --- | --- |
| `API_TOKEN` | required | must match `relays.api_key` on the backend |
| `RELAY_AGENT_PORT` | `8080` | listen port |
| `RELAY_IFACE` | auto | interface name; auto = the interface of the default route |
| `NFT_TABLE` | `chop_relay` | nft table to read |

## Resource envelope

Static binary, stdlib only, ~4 MB. Idle RSS under 8 MB. systemd unit sets
`MemoryMax=32M` and `CPUQuota=10%` as hard ceilings, so a bug cannot take
CPU from the forwarding path. No goroutines at rest besides the listener.

## systemd unit

```
[Unit]
Description=CHOP relay agent (read-only stats)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/relay-agent/.env
ExecStart=/usr/local/bin/relay-agent
Restart=on-failure
RestartSec=3
MemoryMax=32M
CPUQuota=10%
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

`CAP_NET_ADMIN` is what `nft list` and `conntrack -L` need. `AF_NETLINK`
is required because both CLIs talk netlink. Phase 2 (rule writes) will need
`ReadWritePaths=/etc/nftables.conf`; phase 1 does not.

## Install (`install.sh`)

Run as root on a bare Ubuntu 24.04 box, piped over ssh like the other
fleet installers:

```
ssh root@<relay> 'API_TOKEN=<token> bash -s' < install.sh
```

Steps, all idempotent:

1. `apt-get install -y nftables conntrack` (skip if present).
2. Relay prep (the manual recipe from the fleet runbook, now scripted):
   - `/etc/sysctl.d/99-chop-relay.conf`: `ip_forward=1`,
     `nf_conntrack_max=262144`, `nf_conntrack_tcp_timeout_established=3600`
   - `/etc/modules-load.d/chop-relay.conf`: `nf_conntrack`
   - If `/etc/nftables.conf` has no `chop_relay` table: back up the stock
     file to `/etc/nftables.conf.stock` and write the idempotent empty
     `table ip chop_relay` (the `table` / `delete table` / `table {}`
     pattern). **Never touch a file that already has the table** — live
     relays carry DNAT rules there.
   - `sysctl --system`, `nft -f /etc/nftables.conf`, `systemctl enable
     --now nftables`.
3. Download the release binary + `.sha256` from the GitHub release, verify,
   install to `/usr/local/bin/relay-agent`.
4. Write `/etc/relay-agent/.env` (mode 0600) if absent; if present keep the
   existing token unless `API_TOKEN` is given.
5. Install the unit, `daemon-reload`, `enable --now`.
6. Self-check: `curl -H "key: $API_TOKEN" http://127.0.0.1:$PORT/api/health`
   must return 200 with `running: true`, else exit non-zero and print the
   journal tail.

`build.sh` cross-compiles `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` with
`-ldflags="-s -w -X main.version=<tag>"` and writes the `.sha256`,
matching `vless-api`.

## Backend side (separate change, listed for completeness)

- Migration: `relays.api_key` VARCHAR(64) nullable, plus `agent_port`
  SMALLINT default 8080.
- `Relay::agent()` helper returning a tiny HTTP client (6 s timeout,
  `key:` header) with `health()` and `stats()`.
- `relays:agent-poll` artisan command, `everyMinute()`, that stores each
  read into a `relay_stats` table (relay_id, ts, raw JSON) for a first
  observation period. The detector (phase 2 of the wider project) reads
  from there.
- Admin: relay form gets `api_key`; relay table gets an "agent" badge
  (reachable / unreachable / not configured).

None of this is in the agent repo.

## Rollout

1. Build, unit-test, tag `v0.1.0`.
2. Install on the four idle `reserved_clean` spares (relays 30, 33, 34, 35)
   — zero user exposure. Verify `/api/stats` against `nft list` by hand.
3. Install on one live relay off-peak (relay 21, four FR free nodes).
   Confirm forwarding rate unchanged (`ip -s link`, `nft` counters) for an
   hour.
4. Roll to the remaining live relays. Backend poll can start as soon as the
   first agent is up.

## Testing

- **Unit:** `stats_test.go` parses committed fixtures captured from relay 34
  (`testdata/nft-chop_relay.json`, `testdata/conntrack-L.txt`,
  `testdata/proc-net-dev.txt`, `testdata/proc-stat.txt`) and asserts the
  exact `rules[]`, `origins[]`, `box` values. `server_test.go` covers auth
  (missing key → 404, wrong key → 404, right key → 200) and the error paths
  (nft missing table → empty rules + health flag; conntrack failure →
  warning, not 500).
- **Integration (manual, in rollout step 2):** compare the agent's
  `new_flows` delta over 60 s with `nft list` deltas on the same box.
- Parsers are pure functions over `[]byte` so they run without root or
  nftables on the dev Mac.

## Backward compatibility

- The agent adds a listener and nothing else. Forwarding, nftables rules,
  conntrack, and sysctl values it reads are untouched. Uninstalling the
  service returns the box to its previous state exactly.
- `install.sh` never rewrites an `/etc/nftables.conf` that already contains
  `chop_relay`, so running it on a live relay cannot drop DNAT rules.
- Relays without an agent keep working unchanged. The backend poller skips
  relays with `api_key` null; the future detector treats "no agent" as "no
  relay-side signal" and degrades to backend-only alerting.
- Port 8080 is free on every current relay (only origin nodes run APIs on
  8080/8081). `RELAY_AGENT_PORT` exists for a relay co-hosted on a node
  (relay 13 = node 413 runs `wireguard-api` on 8080; use 8082 there).
- Phase 2 will add write endpoints without changing any phase-1 response
  shape; fields are only ever added.

## Open questions (decide at implementation, none block the build)

- Whether `cpu_steal_pct` sampling (100 ms) is worth keeping on `/api/stats`
  or should move to `/api/health`. Default: keep on stats, it is bounded.
- Whether to expose `/metrics` in Prometheus format later for Grafana. Not
  in phase 1; the JSON is the contract.
