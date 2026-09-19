# socksfilter

[<img src="https://img.shields.io/github/license/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/languages/top/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/v/release/esrrhs/socksfilter">](https://github.com/esrrhs/socksfilter/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/socksfilter/total">](https://github.com/esrrhs/socksfilter/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/socksfilter">](https://hub.docker.com/repository/docker/esrrhs/socksfilter)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/socksfilter/go.yml?branch=master">](https://github.com/esrrhs/socksfilter/actions)

A lightweight SOCKS5 traffic routing and aggregation proxy filter.

## Features
* **Standard SOCKS5 Server**: Provides standard SOCKS5 proxy service with optional username and password authentication.
* **Smart Traffic Routing & Bypass**:
  * **Domestic Domain Whitelist Direct**: Built-in accelerated domain whitelist (`accelerated-domains.china.conf`) for instantaneous direct connection.
  * **Private & LAN IP Direct**: Automatically identifies and bypasses private IP ranges (e.g. `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  * **GeoIP Country Filtering**: Filters based on destination IP country code (default `CN`). Matches connect directly; non-matches are routed to upstream SOCKS5 servers.
  * **High-Performance DNS Cache**: Built-in multi-core concurrent LRU cache to reduce redundant DNS lookups.
* **Upstream Multi-Server Load Balancing**: Aggregates multiple backend SOCKS5 servers with flexible load balancing strategies:
  * `robin`: Thread-safe Round-Robin rotation.
  * `rand`: Random selection.
  * `hash_by_dst_ip`: Hash based on destination IP.
  * `hash_by_src_ip`: Hash based on client source IP.
  * `hash_all`: Combined source and destination hash.
  * Automatically skips unreachable backend servers.
* **Graceful Shutdown & Leak Prevention**: Handles `SIGINT` / `SIGTERM` signals for clean listener termination, and features TCP half-close propagation and connection leak prevention.

## Usage

### Command Line
Listen on port 1080, bypass CN traffic directly, and route non-CN traffic through backend SOCKS5 servers:
```bash
./socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```

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
  -file string
    	ip file (default "GeoLite2-Country.mmdb")
  -l string
    	listen addr (default ":1080")
  -loglevel string
    	log level (default "info")
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
  -skip string
    	skip country (default "CN")
  -username string
    	username
  -version
    	show version and exit
```
