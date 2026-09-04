# relay-agent

Read-only stats agent for CHOP relay boxes. One static Go binary, no
dependencies, idle between requests. Reports nftables DNAT counters,
conntrack reply state per origin, and box counters over an authenticated
HTTP API so the backend can tell a blocked relay from a dead one from a
dead origin. Design: `docs/superpowers/specs/2026-09-04-relay-agent-design.md`.

## Install (bare Ubuntu/Debian relay, as root)

    ssh root@<relay> 'API_TOKEN=<token> bash -s' < install.sh

The installer also performs the standard relay prep (ip_forward, conntrack
limits, empty idempotent `chop_relay` table, `nftables.service`). It never
rewrites an `/etc/nftables.conf` that already contains `chop_relay`.

## Environment (`/etc/relay-agent/.env`)

| Var | Default | Meaning |
| --- | --- | --- |
| `API_TOKEN` | required | must match `relays.api_key` on the backend |
| `RELAY_AGENT_PORT` | `8080` | listen port (use 8082 on a box that is also a node) |
| `RELAY_IFACE` | auto | interface; auto = default-route interface |
| `NFT_TABLE` | `chop_relay` | table to read |

## Endpoints (header `key: <API_TOKEN>`; wrong key → 404)

    curl -H "key: $TOKEN" http://<relay>:8080/api/health
    curl -H "key: $TOKEN" http://<relay>:8080/api/stats
    curl -H "key: $TOKEN" http://<relay>:8080/api/rules

`rules[].new_flows` is a nat-hook counter: it counts the first packet of
each flow, not throughput. All counters are cumulative; diff them.

## Build

    ./build.sh v0.1.0      # dist/relay-agent-linux-{amd64,arm64} + .sha256

## Test

    go vet ./... && go test ./...

Parsers are pure functions over fixtures in `testdata/`; no root or Linux
needed.
