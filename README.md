# socksfilter

[<img src="https://img.shields.io/github/license/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/languages/top/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/v/release/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/socksfilter/total">](https://github.com/esrrhs/socksfilter/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/socksfilter">](https://hub.docker.com/repository/docker/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/socksfilter/go.yml?branch=master">](https://github.com/esrrhs/socksfilter/actions)

A lightweight SOCKS5 traffic routing and aggregation proxy filter.

## Features
* **Standard SOCKS5 Server**: Provides standard SOCKS5 proxy service with TCP CONNECT and UDP ASSOCIATE support (RFC 1928 / RFC 1929), along with optional username and password authentication.
* **Full UDP Relay & Forwarding**: Transparently routes UDP datagrams: domestic and private destinations are relayed directly, while foreign destinations are forwarded through upstream SOCKS5 proxies using UDP ASSOCIATE relaying with load balancing.
* **Smart Traffic Routing & Bypass**:
  * **Unified `gohome/dns` Engine**: Powered by `gohome/dns` with zero-config defaults, anti-pollution parallel queries, and instant bypass classification.
  * **Domestic Domain Whitelist Direct**: Built-in accelerated domain whitelist (`accelerated-domains.china.conf`) and domain suffix tree for instantaneous direct connection.
  * **Private & LAN IP Direct**: Automatically identifies and bypasses private IP ranges (e.g. `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  * **GeoIP Country Filtering**: Filters based on destination IP country code (default `CN`). Matches connect directly; non-matches are routed to upstream SOCKS5 servers.
  * **High-Performance DNS Cache**: Built-in multi-core concurrent LRU cache and singleflight deduplication to reduce redundant DNS lookups.
* **Upstream SOCKS5 Authentication**: Forwards username/password credentials (RFC 1929) to upstream SOCKS5 servers for both TCP CONNECT and UDP ASSOCIATE.
* **JSON Config File**: `-config file.json` can supply every flag; explicit command-line flags take precedence.
* **Upstream Health Checks (Active + Passive)**: Actively probes each upstream periodically (TCP connect + SOCKS5 handshake, using `-susername`/`-spassword`), and also learns from real traffic — TCP/UDP dial, handshake, or UDP relay-write failures feed the same health state while successes clear it. An upstream failing two consecutive checks is removed from candidate selection. After a cooldown it enters half-open state and retries with a single request, recovering on success or re-entering cooldown on failure (cooldown equals the probe interval, or 10s when active probing is disabled). If every upstream is down, selection fails open to on-demand failover.
* **Upstream Multi-Server Load Balancing**: Aggregates multiple backend SOCKS5 servers with flexible load balancing strategies:
  * `robin`: Thread-safe Round-Robin rotation.
  * `rand`: Random selection.
  * `hash_by_dst_ip`: Hash based on destination IP.
  * `hash_by_src_ip`: Hash based on client source IP.
  * `hash_all`: Combined source and destination hash.
  * Automatically skips unreachable backend servers.
* **Graceful Shutdown & Leak Prevention**: Handles `SIGINT` / `SIGTERM` signals for clean listener termination, and features TCP half-close propagation and connection leak prevention.
* **Concurrent Session Limit**: With `-max-conn`, caps concurrent SOCKS sessions (TCP CONNECT and UDP ASSOCIATE share one pool). Overflow sessions receive a proper SOCKS5 failure reply instead of being silently reset, and the rejected count is exposed in stats. Disabled (`0`) by default.
* **Runtime Observability Endpoint**: With `-stats-addr` (e.g. `127.0.0.1:7070`), serves plain-text HTTP endpoints (disabled by default):
  * `GET /stats`: uptime, active/total/rejected TCP connections, active/total UDP associations, cumulative relayed bytes per direction, per-egress-route payload bytes (direct bypass plus each upstream, TCP and UDP combined), per-egress-route session counts (`route_sessions`: active gauge and cumulative established total for direct; `sessions_active` per upstream, TCP CONNECT tunnels and UDP sessions combined), route DNS resolution counters (`dns_lookups` by outcome — literal IP / cache hit / resolved / failure — plus `dns_resolved_source` smart-resolver vs system-fallback breakdown and live `cache_entries`), idle-timeout eviction counts (`idle_timeout_closed`: TCP tunnels and UDP associations locally reaped after bidirectional silence), and per-upstream health state (`alive` / `half_open` / `dead` with failure count and removal duration) plus cumulative per-upstream session counters `attempts` / `established` / `connect_fails` (TCP CONNECT and UDP ASSOCIATE combined; UDP session reuse is not counted again).
  * `GET /metrics`: Prometheus text exposition (version 0.0.4) with `socksfilter_*` gauges/counters for sessions, relayed bytes (including `socksfilter_relay_bytes_total{route,direction}` broken down by egress route — `direct` or the upstream address — for both directions), per-route session accounting (`socksfilter_route_sessions_active{route}` gauge and `socksfilter_route_sessions_total{route}` counter; the upstream-route total equals `socksfilter_upstream_sessions_established_total` under the unified route label), DNS resolution metrics (`socksfilter_dns_lookups_total{outcome}` counter for literal/cache_hit/resolved/failure, `socksfilter_dns_resolutions_total{source}` counter for smart_resolver/system_fallback, and `socksfilter_dns_cache_entries` gauge), idle-timeout eviction counters (`socksfilter_idle_timeout_closed_total{transport}` for tcp/udp), the configured session limit, and per-upstream `up` state, consecutive failures and cumulative session attempts/established/connect failures; scrape it directly from Prometheus.
  * `GET /healthz`: liveness probe, always `200 ok` while the process can serve HTTP.
  * `GET /readyz`: readiness probe for container orchestrators — `200` when at least one upstream is selectable, `503` when all upstreams are removed (the data plane itself stays fail-open and keeps trying on demand).

## Usage

### Command Line
Listen on port 1080, bypass CN traffic directly, and route non-CN traffic through backend SOCKS5 servers:
```bash
./socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```

### Configuration File
All flags can optionally be supplied as a JSON file via `-config`:
```json
{
  "l": ":1080",
  "s": "yourserver1:1080 yourserver2:1080",
  "select": "robin",
  "dial-timeout": 10,
  "tcp-keepalive": 30,
  "max-conn": 1000,
  "stats-addr": "127.0.0.1:7070",
  "susername": "user",
  "spassword": "pass"
}
```
```bash
./socksfilter -config /etc/socksfilter/config.json
```
Rules:
- JSON keys are flag names exactly as shown by `-h`; values are strings, numbers, or booleans. Multi-value flags such as `-s` stay space-separated inside one string.
- Precedence: explicit command-line flags > config file > built-in defaults (e.g. `-s cli:1 -config config.json` keeps `cli:1`).
- Unknown keys, malformed JSON, `null`, array/object values, or the `config` key itself make the process exit with an error; an empty `{}` is a no-op.

### Docker
Run directly using the pre-built Docker image:

**Option 1: Port mapping (recommended for macOS, Windows, Linux)**
```bash
docker run --name socksfilter -d --restart=always \
  -p 1080:1080 \
  esrrhs/socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```

**Option 2: Host network mode (best performance on Linux)**
```bash
docker run --name socksfilter -d --restart=always \
  --network host \
  esrrhs/socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```

**Option 3: Mount custom rules or GeoIP database**
```bash
docker run --name socksfilter -d --restart=always \
  -p 1080:1080 \
  -v $(pwd)/GeoLite2-Country.mmdb:/app/GeoLite2-Country.mmdb \
  -v $(pwd)/accelerated-domains.china.conf:/app/accelerated-domains.china.conf \
  esrrhs/socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```

### Build and Development
The project includes a `Makefile` for streamlined development:
```bash
# Build local binary with version info
make build

# Run unit tests with race detection
make test

# Build lightweight Docker image
make docker

# Cross-compile and package release zips (bundles GeoIP and domain rules)
make pack

# Update China domain rules from upstream
make update-rules

# Clean build artifacts
make clean
```

### Command-line Options
Run `./socksfilter -h` to see all available flags:
```
Usage of ./socksfilter:
  -cache_expire int
    	cache expire seconds for dns (default 3600)
  -cache_size int
    	cache size for dns (default 1000)
  -china_domains string
    	china domains file (default "accelerated-domains.china.conf")
  -config string
    	load flags from a JSON config file; explicit command-line flags take precedence
  -dial-timeout int
    	tcp dial timeout in seconds for upstream and direct targets (default 10)
  -file string
    	ip file (default "GeoLite2-Country.mmdb")
  -health-check-interval int
    	upstream health check interval in seconds, 0 to disable (default 30)
  -health-check-timeout int
    	upstream health check timeout in seconds (default 5)
  -idle-timeout int
    	idle timeout in seconds for relayed tcp connections, 0 to disable
  -l string
    	listen addr (default ":1080")
  -loglevel string
    	log level (default "info")
  -max-conn int
    	max concurrent socks sessions (tcp connect and udp associate), 0 to disable
  -nolog int
    	write log file
  -noprint int
    	print stdout
  -password string
    	password
  -s string
    	server addr (default "server1 server2 server3")
  -select string
    	select server robin/rand/hash_by_dst_ip/hash_by_src_ip/hash_all (default "robin")
  -shutdown-timeout int
    	grace period in seconds to wait for in-flight connections on shutdown, 0 to force close immediately (default 10)
  -skip string
    	skip country (default "CN")
  -spassword string
    	upstream server password
  -stats-addr string
    	http listen addr for runtime stats, e.g. 127.0.0.1:7070, empty to disable
  -susername string
    	upstream server username
  -tcp-keepalive int
    	tcp keepalive idle time in seconds for client and upstream connections, 0 to disable (default 30)
  -udp-idle-timeout int
    	idle timeout in seconds for udp associations, 0 to disable (default 300)
  -username string
    	username
  -version
    	show version and exit
```
