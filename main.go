package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/lru"
	"github.com/esrrhs/gohome/network"
	"github.com/esrrhs/gohome/thirdparty"
)

var (
	version = "0.7.17"

	configPath         = flag.String("config", "", "load flags from a JSON config file; explicit command-line flags take precedence")
	listen             = flag.String("l", ":1080", "listen addr")
	servers            = flag.String("s", "server1 server2 server3", "server addr")
	sel                = flag.String("select", "robin", "select server robin/rand/hash_by_dst_ip/hash_by_src_ip/hash_all")
	skip               = flag.String("skip", "CN", "skip country")
	dialTimeoutSec     = flag.Int("dial-timeout", 10, "tcp dial timeout in seconds for upstream and direct targets")
	idleTimeoutSec     = flag.Int("idle-timeout", 0, "idle timeout in seconds for relayed tcp connections, 0 to disable")
	udpIdleTimeoutSec  = flag.Int("udp-idle-timeout", 300, "idle timeout in seconds for udp associations, 0 to disable")
	tcpKeepaliveSec    = flag.Int("tcp-keepalive", 30, "tcp keepalive idle time in seconds for client and upstream connections, 0 to disable")
	shutdownTimeoutSec = flag.Int("shutdown-timeout", 10, "grace period in seconds to wait for in-flight connections on shutdown, 0 to force close immediately")
	filename           = flag.String("file", "GeoLite2-Country.mmdb", "ip file")
	chinaDomains       = flag.String("china_domains", "accelerated-domains.china.conf", "china domains file")
	cache_size         = flag.Int("cache_size", 1000, "cache size for dns")
	cache_expire       = flag.Int("cache_expire", 3600, "cache expire seconds for dns")
	loglevel           = flag.String("loglevel", "info", "log level")
	nolog              = flag.Int("nolog", 0, "write log file")
	noprint            = flag.Int("noprint", 0, "print stdout")
	username           = flag.String("username", "", "username")
	password           = flag.String("password", "", "password")
	susername          = flag.String("susername", "", "upstream server username")
	spassword          = flag.String("spassword", "", "upstream server password")
	healthInterval     = flag.Int("health-check-interval", 30, "upstream health check interval in seconds, 0 to disable")
	healthTimeout      = flag.Int("health-check-timeout", 5, "upstream health check timeout in seconds")
	statsAddr          = flag.String("stats-addr", "", "http listen addr for runtime stats, e.g. 127.0.0.1:7070, empty to disable")
	maxConn            = flag.Int("max-conn", 0, "max concurrent socks sessions (tcp connect and udp associate), 0 to disable")
	showVersion        = flag.Bool("version", false, "show version and exit")
)

var (
	gResolver     dns.Resolver
	gDnsCache     *lru.LRUMultiCache[string, string]
	gChinaDomains map[string]bool
	gRobinIndex   atomic.Uint64

	// gConnWg 跟踪所有已接受连接的处理 goroutine，供优雅关闭排空使用。
	gConnWg sync.WaitGroup

	// 运行时计数器，供 /stats 观测端点读取。
	gStartTime           atomic.Int64 // 进程启动时刻 unix nano，0 表示未初始化
	gActiveTCPConns      atomic.Int64
	gTotalTCPConns       atomic.Int64
	gActiveUDPAssoc      atomic.Int64
	gTotalUDPAssoc       atomic.Int64
	gBytesClientToTarget atomic.Int64 // TCP 中继：客户端 -> 目标 累计字节
	gBytesTargetToClient atomic.Int64 // TCP 中继：目标 -> 客户端 累计字节
	gRejectedConns       atomic.Int64 // 因 -max-conn 上限被拒绝的会话累计数

	// 按出口归因的累计中继字节（TCP 流 + UDP 数据报有效载荷，不含 SOCKS5
	// 封装）：直连出口记入 gRouteBytesDirect*，经上游的流量记入对应
	// upstreamHealth 的 bytesC2T/bytesT2C。c2t = client -> target。
	gRouteBytesDirectC2T atomic.Int64
	gRouteBytesDirectT2C atomic.Int64

	// 按出口归因的会话计数（TCP CONNECT 隧道与 UDP 会话统一口径）：
	// direct 桶保留累计建立数与当前活跃数；经上游的活跃会话记入对应
	// upstreamHealth.sessionsActive，累计建立数复用 established。
	gRouteSessionsTotalDirect  atomic.Int64
	gRouteSessionsActiveDirect atomic.Int64

	// DNS 分流解析观测，埋点在统一入口 resolveRouteIP：
	// 每次域名路由解析按结果四选一计入 gDNSLookups*；IP 字面量目标不查 DNS。
	// gDNSResolveSmart/Fallback 对实际解析成功的来源做细分（二者之和=resolved）。
	gDNSLookupsLiteral  atomic.Int64 // 目标本身是 IP 字面量，无需解析
	gDNSLookupsCacheHit atomic.Int64 // 命中 gDnsCache（host 或 root 域）
	gDNSLookupsResolved atomic.Int64 // 缓存未命中后实际发起解析且成功
	gDNSLookupsFailure  atomic.Int64 // 所有解析路径均失败（按既有行为回退直连）
	gDNSResolveSmart    atomic.Int64 // gResolver 防污染智能解析成功
	gDNSResolveFallback atomic.Int64 // common.ResolveDomainToIP 系统/DoH 兜底成功

	// 因空闲超时被本端主动回收的会话累计数（用于评估 -idle-timeout /
	// -udp-idle-timeout 是否过短误伤、或过长无法清理僵尸会话）。
	gIdleClosedTCP atomic.Int64 // TCP 隧道双向静默超时
	gIdleClosedUDP atomic.Int64 // UDP 关联双向静默超时

	// SOCKS5 入口协议错误累计数（发生在会话建立/准入之前，不计入连接与会话
	// 指标）：可用于发现端口扫描、错误凭据探测或不兼容客户端。
	gEntryErrHandshake      atomic.Int64 // 方法协商/用户名密码认证失败（含非 SOCKS5 流量）
	gEntryErrBadRequest     atomic.Int64 // 握手通过但 CONNECT/UDP 请求帧解析失败
	gEntryErrUnsupportedCmd atomic.Int64 // 请求命令既非 CONNECT 也非 UDP ASSOCIATE
)

// loadFlagsFromConfig 从 JSON 配置文件填充未在命令行显式指定的 flag。
// JSON 的 key 必须与 flag 名一致（如 "s"、"dial-timeout"），value 支持
// JSON string / bool / number（number 以原始词法文本交给 flag 解析，
// 避免浮点精度损失）。命令行显式给出的 flag 优先，配置文件不得覆盖。
func loadFlagsFromConfig(fs *flag.FlagSet, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var vals map[string]any
	if err := dec.Decode(&vals); err != nil {
		return fmt.Errorf("parse config %q: %w", path, err)
	}

	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	names := make([]string, 0, len(vals))
	for k := range vals {
		names = append(names, k)
	}
	slices.Sort(names) // 稳定错误顺序

	for _, name := range names {
		if name == "config" {
			return fmt.Errorf("config %q: flag %q cannot be set inside the config file", path, name)
		}
		f := fs.Lookup(name)
		if f == nil {
			return fmt.Errorf("config %q: unknown flag %q", path, name)
		}
		if explicit[name] {
			continue // 命令行显式指定，优先级最高
		}
		text, err := configValueText(vals[name])
		if err != nil {
			return fmt.Errorf("config %q: flag %q: %w", path, name, err)
		}
		if err := fs.Set(name, text); err != nil {
			return fmt.Errorf("config %q: set -%s=%q: %w", path, name, text, err)
		}
	}
	return nil
}

// configValueText 把 JSON 值转换为 flag.Value.Set 接受的文本形式。
func configValueText(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case json.Number:
		return x.String(), nil
	case nil:
		return "", errors.New("null is not a valid flag value")
	default:
		return "", fmt.Errorf("unsupported value type %T (only string/number/boolean)", v)
	}
}

func main() {
	flag.Parse()

	if *configPath != "" {
		if err := loadFlagsFromConfig(flag.CommandLine, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	if *showVersion {
		fmt.Printf("socksfilter version %s\n", version)
		return
	}

	if *servers == "" || *servers == "server1 server2 server3" {
		fmt.Print("need servers\n")
		flag.Usage()
		return
	}

	level := loggo.LEVEL_INFO
	if loggo.NameToLevel(*loglevel) >= 0 {
		level = loggo.NameToLevel(*loglevel)
	}
	loggo.Ini(loggo.Config{
		Level:     level,
		Prefix:    "socksfilter",
		MaxDay:    3,
		NoLogFile: *nolog > 0,
		NoPrint:   *noprint > 0,
	})
	loggo.Info("start socksfilter %s...", version)
	gStartTime.Store(time.Now().UnixNano())

	init_env()

	if *statsAddr != "" {
		_, stopStats, err := startStatsServer(*statsAddr)
		if err != nil {
			loggo.Error("stats server listen fail: %s", err)
			return
		}
		defer stopStats()
	}

	if *healthInterval > 0 {
		interval := time.Duration(*healthInterval) * time.Second
		timeout := time.Duration(*healthTimeout) * time.Second
		gHealthCooldown.Store(int64(interval))
		loggo.Info("upstream health check enabled: interval %s timeout %s", interval, timeout)
		go healthCheckLoop(interval, timeout)
	} else {
		loggo.Info("upstream active health check disabled, passive feedback cooldown %s",
			time.Duration(gHealthCooldown.Load()))
	}

	tcpaddr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		loggo.Error("listen fail %s", err)
		return
	}

	tcplistenConn, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		loggo.Error("Error listening for tcp packets: %s", err)
		return
	}
	defer tcplistenConn.Close()
	loggo.Info("listen ok %s", tcpaddr.String())

	// sigCtx 在收到关闭信号时取消：停止接受新连接；
	// drainCtx 在排空窗口结束（或进程退出）时取消：强制中断存量连接。
	sigCtx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	drainCtx, cancelDrain := context.WithCancel(context.Background())
	defer cancelDrain()

	go func() {
		<-sigCtx.Done()
		loggo.Info("received shutdown signal, stopping listener...")
		_ = tcplistenConn.Close()
	}()

	serve(sigCtx, drainCtx, tcplistenConn)

	// listener 已停止接受新连接，进入优雅排空：等待存量连接自然结束。
	grace := shutdownTimeout()
	if grace > 0 {
		loggo.Info("draining in-flight connections, grace period %s", grace)
		if waitForDrain(grace) {
			loggo.Info("all in-flight connections finished, shutdown complete")
			return
		}
		loggo.Info("grace period elapsed, force closing in-flight connections")
	} else {
		loggo.Info("shutdown grace disabled, force closing in-flight connections")
	}
	cancelDrain()
	gConnWg.Wait()
	loggo.Info("shutdown complete")
}

// serve 接受并分发连接。sigCtx 取消后停止接受新连接并返回；
// 每个连接的处理 goroutine 注册到 gConnWg，并通过 drainCtx 响应强制关闭。
func serve(sigCtx, drainCtx context.Context, ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			select {
			case <-sigCtx.Done():
				return
			default:
				loggo.Info("Error accept tcp %s", err)
				continue
			}
		}

		gConnWg.Add(1)
		gActiveTCPConns.Add(1)
		gTotalTCPConns.Add(1)
		go func(c *net.TCPConn) {
			defer gConnWg.Done()
			defer gActiveTCPConns.Add(-1)
			enableTCPKeepAlive(c)
			process(drainCtx, c)
		}(conn)
	}
}

// waitForDrain 等待所有存量连接结束；timeout<=0 时不等待。
// 返回 true 表示在超时前全部自然结束，false 表示超时需要强制关闭。
func waitForDrain(timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	done := make(chan struct{})
	go func() {
		gConnWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// shutdownTimeout 返回关闭时的排空等待时长；0 表示不等待立即强制关闭。
func shutdownTimeout() time.Duration {
	if *shutdownTimeoutSec > 0 {
		return time.Duration(*shutdownTimeoutSec) * time.Second
	}
	return 0
}

// startStatsServer 在 addr 上拉起仅暴露 /stats 的本地 HTTP 服务，
// 返回实际监听地址与停止函数。addr 支持 ":0"，便于测试获取随机端口。
func startStatsServer(addr string) (string, func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)
	srv := &http.Server{Handler: mux}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			loggo.Info("stats server stopped: %s", serveErr)
		}
	}()
	stop := func() { _ = srv.Close() }
	loggo.Info("observability endpoint listening on http://%s ({/stats,/metrics,/healthz,/readyz})", ln.Addr().String())
	return ln.Addr().String(), stop, nil
}

// renderStats 生成运行时快照文本，独立于 HTTP 以便测试。
func renderStats(now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "socksfilter %s\n", version)

	startNano := gStartTime.Load()
	if startNano == 0 {
		startNano = now.UnixNano()
	}
	fmt.Fprintf(&b, "uptime: %s\n", now.Sub(time.Unix(0, startNano)).Round(time.Second))
	fmt.Fprintf(&b, "tcp_connections: active=%d total=%d rejected=%d\n",
		gActiveTCPConns.Load(), gTotalTCPConns.Load(), gRejectedConns.Load())
	fmt.Fprintf(&b, "udp_associations: active=%d total=%d\n",
		gActiveUDPAssoc.Load(), gTotalUDPAssoc.Load())
	if *maxConn > 0 {
		fmt.Fprintf(&b, "max_conn: %d\n", *maxConn)
	} else {
		b.WriteString("max_conn: 0 (disabled)\n")
	}
	fmt.Fprintf(&b, "tcp_relay_bytes: client_to_target=%d target_to_client=%d\n",
		gBytesClientToTarget.Load(), gBytesTargetToClient.Load())
	fmt.Fprintf(&b, "route_relay_bytes(tcp+udp payload): direct_c2t=%d direct_t2c=%d\n",
		gRouteBytesDirectC2T.Load(), gRouteBytesDirectT2C.Load())
	fmt.Fprintf(&b, "route_sessions(tcp+udp): direct_active=%d direct_total=%d\n",
		gRouteSessionsActiveDirect.Load(), gRouteSessionsTotalDirect.Load())
	fmt.Fprintf(&b, "dns_lookups: literal=%d cache_hit=%d resolved=%d failure=%d\n",
		gDNSLookupsLiteral.Load(), gDNSLookupsCacheHit.Load(),
		gDNSLookupsResolved.Load(), gDNSLookupsFailure.Load())
	fmt.Fprintf(&b, "dns_resolved_source: smart_resolver=%d system_fallback=%d cache_entries=%d\n",
		gDNSResolveSmart.Load(), gDNSResolveFallback.Load(), dnsCacheSize())
	fmt.Fprintf(&b, "idle_timeout_closed: tcp=%d udp=%d\n",
		gIdleClosedTCP.Load(), gIdleClosedUDP.Load())
	fmt.Fprintf(&b, "entry_errors: handshake=%d bad_request=%d unsupported_command=%d\n",
		gEntryErrHandshake.Load(), gEntryErrBadRequest.Load(), gEntryErrUnsupportedCmd.Load())

	b.WriteString("upstreams:\n")
	for _, server := range strings.Fields(*servers) {
		h := getUpstreamHealth(server)
		state := h.state(now)
		fmt.Fprintf(&b, "  %s: state=%s fails=%d attempts=%d established=%d connect_fails=%d bytes_c2t=%d bytes_t2c=%d sessions_active=%d probe_attempts=%d probe_fails=%d probe_last_ms=%.3f probe_avg_ms=%.3f marked_dead=%d recovered=%d traffic_dial=%d traffic_handshake=%d traffic_request=%d traffic_write=%d",
			server, state, h.fails.Load(), h.attempts.Load(), h.established.Load(), h.connectFails.Load(),
			h.bytesC2T.Load(), h.bytesT2C.Load(), h.sessionsActive.Load(),
			h.probeAttempts.Load(), h.probeFails.Load(),
			float64(h.probeLastNS.Load())/1e6, probeAvgMS(h),
			h.markedDead.Load(), h.recovered.Load(),
			h.trafficFailsDial.Load(), h.trafficFailsHandshake.Load(), h.trafficFailsRequest.Load(), h.trafficFailsWrite.Load())
		if state == "dead" || state == "half_open" {
			if deadAt := h.deadAt.Load(); deadAt > 0 {
				fmt.Fprintf(&b, " removed_since=%s", now.Sub(time.Unix(0, deadAt)).Round(time.Second))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// allowProbeMethod 仅允许 GET/HEAD 访问观测端点，其他方法回 405。
// 返回 false 时调用方必须直接结束处理。
func allowProbeMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	return true
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if !allowProbeMethod(w, r) {
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(renderStats(time.Now())))
}

// promLabelValue 按 Prometheus 文本格式要求转义标签值。
func promLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// formatProbeSeconds 将纳秒探测耗时格式化为 Prometheus 秒值（6 位小数）。
func formatProbeSeconds(ns int64) string {
	return strconv.FormatFloat(float64(ns)/float64(time.Second), 'f', 6, 64)
}

// renderPrometheusMetrics 生成 Prometheus 文本格式（0.0.4）快照，独立于 HTTP
// 以便测试。所有指标带 socksfilter_ 前缀；_total 后缀保证单调不减，
// upstream_failures 会被成功清零，因此作为 gauge 暴露。
func renderPrometheusMetrics(now time.Time) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# HELP socksfilter_build_info Build version information.\n# TYPE socksfilter_build_info gauge\nsocksfilter_build_info{version=\"%s\"} 1\n",
		promLabelValue(version))

	b.WriteString("# HELP socksfilter_tcp_connections_active Currently active TCP proxy sessions.\n# TYPE socksfilter_tcp_connections_active gauge\n")
	fmt.Fprintf(&b, "socksfilter_tcp_connections_active %d\n", gActiveTCPConns.Load())
	b.WriteString("# HELP socksfilter_tcp_connections_total Total accepted TCP proxy sessions.\n# TYPE socksfilter_tcp_connections_total counter\n")
	fmt.Fprintf(&b, "socksfilter_tcp_connections_total %d\n", gTotalTCPConns.Load())
	b.WriteString("# HELP socksfilter_tcp_connections_rejected_total Total sessions rejected by the -max-conn limit.\n# TYPE socksfilter_tcp_connections_rejected_total counter\n")
	fmt.Fprintf(&b, "socksfilter_tcp_connections_rejected_total %d\n", gRejectedConns.Load())

	b.WriteString("# HELP socksfilter_udp_associations_active Currently active UDP associations.\n# TYPE socksfilter_udp_associations_active gauge\n")
	fmt.Fprintf(&b, "socksfilter_udp_associations_active %d\n", gActiveUDPAssoc.Load())
	b.WriteString("# HELP socksfilter_udp_associations_total Total accepted UDP associations.\n# TYPE socksfilter_udp_associations_total counter\n")
	fmt.Fprintf(&b, "socksfilter_udp_associations_total %d\n", gTotalUDPAssoc.Load())

	b.WriteString("# HELP socksfilter_tcp_relay_bytes_total Cumulative relayed TCP payload bytes.\n# TYPE socksfilter_tcp_relay_bytes_total counter\n")
	fmt.Fprintf(&b, "socksfilter_tcp_relay_bytes_total{direction=\"%s\"} %d\n",
		"client_to_target", gBytesClientToTarget.Load())
	fmt.Fprintf(&b, "socksfilter_tcp_relay_bytes_total{direction=\"%s\"} %d\n",
		"target_to_client", gBytesTargetToClient.Load())

	// 按出口归因的中继有效载荷字节（TCP 流 + UDP 数据报，不含 SOCKS5 封装）：
	// route="direct" 为分流直连，其余标签值为具体上游地址。
	b.WriteString("# HELP socksfilter_relay_bytes_total Cumulative payload bytes relayed per egress route (TCP streams plus UDP datagrams, excluding SOCKS5 framing); route \"direct\" is bypass traffic.\n# TYPE socksfilter_relay_bytes_total counter\n")
	fmt.Fprintf(&b, "socksfilter_relay_bytes_total{route=\"%s\",direction=\"%s\"} %d\n",
		"direct", "client_to_target", gRouteBytesDirectC2T.Load())
	fmt.Fprintf(&b, "socksfilter_relay_bytes_total{route=\"%s\",direction=\"%s\"} %d\n",
		"direct", "target_to_client", gRouteBytesDirectT2C.Load())

	// 按出口归因的会话：活跃 gauge 与累计建立 counter（TCP CONNECT 隧道 +
	// UDP 会话）。route="direct" 为分流直连；上游路由的 total 与
	// socksfilter_upstream_sessions_established_total 同值，仅标签口径统一为 route。
	b.WriteString("# HELP socksfilter_route_sessions_active Currently active sessions egressing through this route (established TCP CONNECT tunnels and UDP sessions).\n# TYPE socksfilter_route_sessions_active gauge\n")
	fmt.Fprintf(&b, "socksfilter_route_sessions_active{route=\"%s\"} %d\n",
		"direct", gRouteSessionsActiveDirect.Load())
	b.WriteString("# HELP socksfilter_route_sessions_total Total sessions established via this egress route (TCP CONNECT tunnels and UDP sessions).\n# TYPE socksfilter_route_sessions_total counter\n")
	fmt.Fprintf(&b, "socksfilter_route_sessions_total{route=\"%s\"} %d\n",
		"direct", gRouteSessionsTotalDirect.Load())

	// DNS 分流解析：lookup 按结果互斥分类（literal 为 IP 字面量目标，不查 DNS）；
	// resolution 按实际解析成功的来源细分；cache_entries 为当前缓存条目 gauge。
	b.WriteString("# HELP socksfilter_dns_lookups_total Route-resolution lookups by outcome; \"literal\" targets are IPs needing no DNS, the rest are domain lookups.\n# TYPE socksfilter_dns_lookups_total counter\n")
	fmt.Fprintf(&b, "socksfilter_dns_lookups_total{outcome=\"%s\"} %d\n", "literal", gDNSLookupsLiteral.Load())
	fmt.Fprintf(&b, "socksfilter_dns_lookups_total{outcome=\"%s\"} %d\n", "cache_hit", gDNSLookupsCacheHit.Load())
	fmt.Fprintf(&b, "socksfilter_dns_lookups_total{outcome=\"%s\"} %d\n", "resolved", gDNSLookupsResolved.Load())
	fmt.Fprintf(&b, "socksfilter_dns_lookups_total{outcome=\"%s\"} %d\n", "failure", gDNSLookupsFailure.Load())
	b.WriteString("# HELP socksfilter_dns_resolutions_total Successful on-demand domain resolutions by source (smart_resolver or system_fallback).\n# TYPE socksfilter_dns_resolutions_total counter\n")
	fmt.Fprintf(&b, "socksfilter_dns_resolutions_total{source=\"%s\"} %d\n", "smart_resolver", gDNSResolveSmart.Load())
	fmt.Fprintf(&b, "socksfilter_dns_resolutions_total{source=\"%s\"} %d\n", "system_fallback", gDNSResolveFallback.Load())
	b.WriteString("# HELP socksfilter_dns_cache_entries Current entries held in the route DNS cache.\n# TYPE socksfilter_dns_cache_entries gauge\n")
	fmt.Fprintf(&b, "socksfilter_dns_cache_entries %d\n", dnsCacheSize())

	// 被空闲超时（-idle-timeout / -udp-idle-timeout）主动回收的会话累计数。
	b.WriteString("# HELP socksfilter_idle_timeout_closed_total Sessions closed locally after bidirectional idle timeout (tcp tunnels and udp associations).\n# TYPE socksfilter_idle_timeout_closed_total counter\n")
	fmt.Fprintf(&b, "socksfilter_idle_timeout_closed_total{transport=\"%s\"} %d\n", "tcp", gIdleClosedTCP.Load())
	fmt.Fprintf(&b, "socksfilter_idle_timeout_closed_total{transport=\"%s\"} %d\n", "udp", gIdleClosedUDP.Load())

	// SOCKS5 入口协议错误（会话建立前被拒）：握手/认证失败、畸形请求、不支持的命令。
	b.WriteString("# HELP socksfilter_entry_errors_total Client connections rejected before a session was admitted, by SOCKS5 entry-stage reason.\n# TYPE socksfilter_entry_errors_total counter\n")
	fmt.Fprintf(&b, "socksfilter_entry_errors_total{reason=\"%s\"} %d\n", "handshake", gEntryErrHandshake.Load())
	fmt.Fprintf(&b, "socksfilter_entry_errors_total{reason=\"%s\"} %d\n", "bad_request", gEntryErrBadRequest.Load())
	fmt.Fprintf(&b, "socksfilter_entry_errors_total{reason=\"%s\"} %d\n", "unsupported_command", gEntryErrUnsupportedCmd.Load())

	b.WriteString("# HELP socksfilter_max_connections Configured concurrent session limit; 0 means unlimited.\n# TYPE socksfilter_max_connections gauge\n")
	fmt.Fprintf(&b, "socksfilter_max_connections %d\n", *maxConn)

	b.WriteString("# HELP socksfilter_upstream_up 1 if the upstream can serve traffic (alive or half-open probe), 0 if removed.\n# TYPE socksfilter_upstream_up gauge\n")
	b.WriteString("# HELP socksfilter_upstream_health_state Current three-way health state of the upstream; exactly one state per upstream is 1 (one-hot): alive serves traffic, half_open is removed but past the probe cooldown and eligible for trial routing, dead is removed and inside the cooldown window.\n# TYPE socksfilter_upstream_health_state gauge\n")
	b.WriteString("# HELP socksfilter_upstream_consecutive_failures Consecutive passive health failures counted since the last success (0 on healthy).\n# TYPE socksfilter_upstream_consecutive_failures gauge\n")
	b.WriteString("# HELP socksfilter_upstream_session_attempts_total Total session establishment attempts via this upstream (TCP CONNECT plus UDP ASSOCIATE; reused UDP sessions not recounted).\n# TYPE socksfilter_upstream_session_attempts_total counter\n")
	b.WriteString("# HELP socksfilter_upstream_sessions_established_total Total sessions established successfully via this upstream.\n# TYPE socksfilter_upstream_sessions_established_total counter\n")
	b.WriteString("# HELP socksfilter_upstream_connect_failures_total Total session establishment failures via this upstream.\n# TYPE socksfilter_upstream_connect_failures_total counter\n")
	b.WriteString("# HELP socksfilter_upstream_health_probes_total Active health-check probes against this upstream by outcome.\n# TYPE socksfilter_upstream_health_probes_total counter\n")
	b.WriteString("# HELP socksfilter_upstream_health_probe_last_duration_seconds Latency of the most recent active health-check probe (TCP connect plus SOCKS5 handshake; 0 until the first probe).\n# TYPE socksfilter_upstream_health_probe_last_duration_seconds gauge\n")
	b.WriteString("# HELP socksfilter_upstream_health_probe_duration_seconds Active health-check probe latency (TCP connect plus SOCKS5 handshake) in seconds; both successful and failed probes are observed.\n# TYPE socksfilter_upstream_health_probe_duration_seconds histogram\n")
	b.WriteString("# HELP socksfilter_upstream_health_transitions_total Cumulative health state transitions of this upstream (marked_dead: alive to removed; recovered: removed to alive); driven by active probes and passive traffic feedback.\n# TYPE socksfilter_upstream_health_transitions_total counter\n")
	b.WriteString("# HELP socksfilter_upstream_traffic_failures_total Passive real-traffic failures while using this upstream, by failure stage (dial: TCP connect; handshake: SOCKS5 method/auth handshake; request: CONNECT/UDP-ASSOCIATE request phase, including target-unreachable replies, counted without affecting health; write: relay write after the session was up); active health probes are excluded.\n# TYPE socksfilter_upstream_traffic_failures_total counter\n")
	for _, server := range strings.Fields(*servers) {
		h := getUpstreamHealth(server)
		up := int64(0)
		if h.isAlive(now) {
			up = 1
		}
		label := fmt.Sprintf("{upstream=\"%s\"}", promLabelValue(server))
		fmt.Fprintf(&b, "socksfilter_upstream_up%s %d\n", label, up)
		currentState := h.state(now)
		for _, st := range upstreamHealthStates {
			v := 0
			if st == currentState {
				v = 1
			}
			fmt.Fprintf(&b, "socksfilter_upstream_health_state{upstream=\"%s\",state=\"%s\"} %d\n",
				promLabelValue(server), st, v)
		}
		fmt.Fprintf(&b, "socksfilter_upstream_consecutive_failures%s %d\n", label, h.fails.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_session_attempts_total%s %d\n", label, h.attempts.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_sessions_established_total%s %d\n", label, h.established.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_connect_failures_total%s %d\n", label, h.connectFails.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_probes_total{upstream=\"%s\",outcome=\"success\"} %d\n",
			promLabelValue(server), h.probeAttempts.Load()-h.probeFails.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_probes_total{upstream=\"%s\",outcome=\"failure\"} %d\n",
			promLabelValue(server), h.probeFails.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_probe_last_duration_seconds{upstream=\"%s\"} %s\n",
			promLabelValue(server), formatProbeSeconds(h.probeLastNS.Load()))
		// 直方图观测桶以非累积形式存储，渲染时现场累加；+Inf/count 取探测总次数。
		var bucketCumulative int64
		for i, upperBound := range probeLatencyUpperBounds {
			bucketCumulative += h.probeLatencyBuckets[i].Load()
			fmt.Fprintf(&b, "socksfilter_upstream_health_probe_duration_seconds_bucket{upstream=\"%s\",le=\"%s\"} %d\n",
				promLabelValue(server), strconv.FormatFloat(upperBound, 'f', -1, 64), bucketCumulative)
		}
		fmt.Fprintf(&b, "socksfilter_upstream_health_probe_duration_seconds_bucket{upstream=\"%s\",le=\"+Inf\"} %d\n",
			promLabelValue(server), h.probeAttempts.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_probe_duration_seconds_sum{upstream=\"%s\"} %s\n",
			promLabelValue(server), formatProbeSeconds(h.probeSumNS.Load()))
		fmt.Fprintf(&b, "socksfilter_upstream_health_probe_duration_seconds_count{upstream=\"%s\"} %d\n",
			promLabelValue(server), h.probeAttempts.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_transitions_total{upstream=\"%s\",event=\"marked_dead\"} %d\n",
			promLabelValue(server), h.markedDead.Load())
		fmt.Fprintf(&b, "socksfilter_upstream_health_transitions_total{upstream=\"%s\",event=\"recovered\"} %d\n",
			promLabelValue(server), h.recovered.Load())
		for _, stage := range trafficFailStages {
			fmt.Fprintf(&b, "socksfilter_upstream_traffic_failures_total{upstream=\"%s\",stage=\"%s\"} %d\n",
				promLabelValue(server), stage, h.trafficFailCount(stage))
		}
		routeLabel := fmt.Sprintf("{route=\"%s\"", promLabelValue(server))
		fmt.Fprintf(&b, "socksfilter_relay_bytes_total%s,direction=\"%s\"} %d\n",
			routeLabel, "client_to_target", h.bytesC2T.Load())
		fmt.Fprintf(&b, "socksfilter_relay_bytes_total%s,direction=\"%s\"} %d\n",
			routeLabel, "target_to_client", h.bytesT2C.Load())
		fmt.Fprintf(&b, "socksfilter_route_sessions_active{route=\"%s\"} %d\n",
			promLabelValue(server), h.sessionsActive.Load())
		fmt.Fprintf(&b, "socksfilter_route_sessions_total{route=\"%s\"} %d\n",
			promLabelValue(server), h.established.Load())
	}
	return b.String()
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !allowProbeMethod(w, r) {
		return
	}
	// Prometheus 解析器要求显式声明 exposition format 版本。
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(renderPrometheusMetrics(time.Now())))
}

// handleHealthz 存活探针：观测 HTTP 服务本身能响应即代表进程存活，恒返回 200。
// 供容器编排（livenessProbe）判断是否需要重启实例。
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !allowProbeMethod(w, r) {
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

// readinessSummary 统计当前可参与选路（存活或冷却期满进入半开试探）与
// 被摘除的上游数量。
func readinessSummary(now time.Time) (alive, dead int) {
	for _, server := range strings.Fields(*servers) {
		if getUpstreamHealth(server).isAlive(now) {
			alive++
		} else {
			dead++
		}
	}
	return alive, dead
}

// renderReadyz 生成就绪探针响应：ready 为 true 表示至少一个上游可参与选路
// （alive 或冷却期满的 half_open）。响应体首行给出 alive/dead/half_open/total
// 汇总，随后逐上游列出三态与摘除时长，便于编排层在 503 时直接定位故障节点。
func renderReadyz(now time.Time) (ready bool, body string) {
	list := strings.Fields(*servers)
	if len(list) == 0 {
		return false, "not ready: no upstreams configured\n"
	}

	var aliveN, halfOpenN, deadN int
	lines := make([]string, 0, len(list))
	for _, server := range list {
		h := getUpstreamHealth(server)
		st := h.state(now)
		switch st {
		case "alive":
			aliveN++
		case "half_open":
			halfOpenN++
		default:
			deadN++
		}
		line := "  " + server + ": state=" + st
		if st != "alive" {
			if deadAt := h.deadAt.Load(); deadAt > 0 {
				line += " removed_since=" + now.Sub(time.Unix(0, deadAt)).Round(time.Second).String()
			}
		}
		lines = append(lines, line)
	}

	var b strings.Builder
	if aliveN+halfOpenN > 0 {
		fmt.Fprintf(&b, "ready: upstreams alive=%d dead=%d half_open=%d total=%d\n",
			aliveN, deadN, halfOpenN, len(list))
	} else {
		fmt.Fprintf(&b, "not ready: all %d upstreams are dead (alive=0 half_open=0 total=%d)\n",
			deadN, len(list))
	}
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return aliveN+halfOpenN > 0, b.String()
}

// handleReadyz 就绪探针：至少一个上游可参与选路时返回 200；全部处于摘除
// 状态（或未配置上游）时返回 503，供 readinessProbe 在故障窗口摘除流量。
// 注意数据面仍是 fail-open 语义：即使全部上游故障，sf 也会按需尝试拨号，
// 探针只反映当前上游健康概况，不中断转发。
func handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !allowProbeMethod(w, r) {
		return
	}
	ready, body := renderReadyz(time.Now())
	if ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(body))
}

func init_env() {
	err := thirdparty.LoadGeoip2(*filename)
	if err != nil {
		loggo.Error("Load Sock5 ip file ERROR: %s", err.Error())
	}

	gDnsCache = lru.NewLRUMultiCache[string, string](
		runtime.NumCPU(),
		*cache_size,
		time.Duration(*cache_expire)*time.Second,
	)

	cfg := dns.DefaultConfig()
	cfg.EnableFakeIP = false // socksfilter 工作在真实目标判定模式，关闭 Fake-IP
	cfg.GeoIPFile = *filename
	if *chinaDomains != "" {
		cfg.DirectDomainFiles = []string{*chinaDomains}
	}
	r, err := dns.NewResolver(cfg)
	if err != nil {
		loggo.Error("Init dns.Resolver error: %s", err)
	} else {
		gResolver = r
	}

	load_china_domains()
}

func load_china_domains() {
	gChinaDomains = make(map[string]bool)
	file, err := os.Open(*chinaDomains)
	if err != nil {
		loggo.Error("load_china_domains read file error: %s", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "server=/") {
			params := strings.Split(line, "/")
			if len(params) >= 3 {
				host := params[1]
				gChinaDomains[host] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		loggo.Error("load_china_domains scan error: %s", err)
		return
	}
	loggo.Info("load_china_domains load ok: %d", len(gChinaDomains))
}

// isDirectIP 判断 IP 是否应当无条件直连：回环、私有、链路本地、CGNAT、未指定地址。
// common.IsPrivateIP 未覆盖 127.0.0.0/8、::1、169.254/16、100.64/10，这里统一补齐。
func isDirectIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if cgnatNet.Contains(ip) {
		return true
	}
	return false
}

var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// resolveRouteIP 把目标（域名或 IP）解析为用于分流判定的真实 IP。
// 解析顺序：gDnsCache 缓存 -> gResolver 防污染智能解析 -> DoH 兜底。
// 解析结果统一回填 gDnsCache，保证 TCP/UDP 的分流判定与实际拨号使用同一 IP。
func resolveRouteIP(host, rootHost string) (string, bool) {
	if common.IsValidIP(rootHost) {
		gDNSLookupsLiteral.Add(1)
		return rootHost, true
	}

	if cacheAddr, ok := gDnsCache.Get(host); ok && cacheAddr != "" {
		gDNSLookupsCacheHit.Add(1)
		loggo.Info("need_proxy cache hit: %s %v", host, cacheAddr)
		return cacheAddr, true
	}
	if rootCacheAddr, ok := gDnsCache.Get(rootHost); ok && rootCacheAddr != "" {
		gDNSLookupsCacheHit.Add(1)
		loggo.Info("need_proxy cache root hit: %s %v", rootHost, rootCacheAddr)
		return rootCacheAddr, true
	}

	if gResolver != nil {
		if ip, err := gResolver.ResolveOne(context.Background(), rootHost); err == nil && ip != nil {
			taddr := ip.String()
			gDnsCache.Set(rootHost, taddr)
			gDNSLookupsResolved.Add(1)
			gDNSResolveSmart.Add(1)
			loggo.Info("need_proxy cache root set via gResolver: %s %s", rootHost, taddr)
			return taddr, true
		} else if err != nil {
			loggo.Error("need_proxy gResolver resolve error: %s %s", rootHost, err)
		}
	}

	if taddr, err := common.ResolveDomainToIP(rootHost); err == nil {
		gDnsCache.Set(rootHost, taddr)
		gDNSLookupsResolved.Add(1)
		gDNSResolveFallback.Add(1)
		loggo.Info("need_proxy cache root set: %s %s size %v", rootHost, taddr, gDnsCache.Size())
		return taddr, true
	} else {
		loggo.Error("need_proxy ResolveDomainToIP root error: %s %s", rootHost, err)
	}

	if taddr, err := common.ResolveDomainToIP(host); err == nil {
		gDnsCache.Set(host, taddr)
		gDNSLookupsResolved.Add(1)
		gDNSResolveFallback.Add(1)
		loggo.Info("need_proxy cache set: %s %s size %v", host, taddr, gDnsCache.Size())
		return taddr, true
	} else {
		loggo.Error("need_proxy ResolveDomainToIP error: %s %s", host, err)
	}

	gDNSLookupsFailure.Add(1)
	return "", false
}

// dnsCacheSize 返回当前 DNS 缓存条目数；init_env 未执行（如纯渲染测试）时为 0。
func dnsCacheSize() int64 {
	if gDnsCache == nil {
		return 0
	}
	return int64(gDnsCache.Size())
}

func need_proxy(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		loggo.Error("SplitHostPort error: %s", err)
		return false
	}

	root_host, err := common.GetRootDomain(addr)
	if err != nil {
		loggo.Error("GetRootDomain error: %s", err)
		return false
	}

	if ok, find := gChinaDomains[root_host]; find && ok {
		loggo.Info("china domain direct: %s %s", root_host, addr)
		return false
	}

	taddr, ok := resolveRouteIP(host, root_host)
	if !ok {
		// 域名解析全部失败时保持既有行为：直连尝试
		return false
	}

	if isDirectIP(taddr) {
		loggo.Info("private ip direct: %s %s", addr, taddr)
		return false
	}

	ret, err := thirdparty.GetGeoipCountryIsoCode(taddr)
	if err != nil {
		return false
	}
	if len(ret) <= 0 {
		loggo.Info("get country empty direct: %s %s", addr, taddr)
		return false
	}

	loggo.Info("need_proxy GetGeoipCountryIsoCode: %s %s %s", addr, taddr, ret)

	return ret != *skip
}

// getCandidateServers 返回按负载均衡策略排序、并经健康检查过滤后的上游列表。
func getCandidateServers(targetAddr string, srcIP string, srcAddr string) []string {
	return filterAliveServers(orderedCandidateServers(targetAddr, srcIP, srcAddr))
}

func orderedCandidateServers(targetAddr string, srcIP string, srcAddr string) []string {
	ss := strings.Fields(*servers)
	if len(ss) <= 0 {
		return nil
	}
	res := make([]string, 0, len(ss))
	switch *sel {
	case "robin":
		offset := int(gRobinIndex.Add(1) - 1)
		for i := 0; i < len(ss); i++ {
			res = append(res, ss[(offset+i)%len(ss)])
		}
	case "rand":
		indexes := rand.Perm(len(ss))
		for _, idx := range indexes {
			res = append(res, ss[idx])
		}
	case "hash_by_dst_ip":
		dsthost, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return ss
		}
		hash := int(common.HashString(dsthost) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			res = append(res, ss[(hash+i)%len(ss)])
		}
	case "hash_by_src_ip":
		hash := int(common.HashString(srcIP) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			res = append(res, ss[(hash+i)%len(ss)])
		}
	case "hash_all":
		hash := int(common.HashString(srcAddr+"-"+targetAddr) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			res = append(res, ss[(hash+i)%len(ss)])
		}
	default:
		loggo.Error("select type error: %s", *sel)
		return ss
	}
	return res
}

const healthFailThreshold = 2

// gHealthCooldown 上游被摘除后进入半开重试的冷却时长。主动探测开启时取探测
// 间隔，关闭时使用默认值 10s，保证纯被动反馈模式下故障节点也能自动恢复。
var gHealthCooldown atomic.Int64

func init() {
	gHealthCooldown.Store(int64(10 * time.Second))
}

type upstreamHealth struct {
	alive  atomic.Bool
	fails  atomic.Int64
	deadAt atomic.Int64 // 被摘除时刻（unix nano），0 表示从未被摘除

	// 累计流量观测计数器（只增不减，不参与健康判定与选路）：
	// attempts 与 established/connectFails 的差值即建立在途的会话数。
	attempts     atomic.Int64 // 经该上游的会话建立尝试次数（TCP CONNECT / UDP ASSOCIATE）
	established  atomic.Int64 // 会话建立成功次数（建立成功瞬间入账）
	connectFails atomic.Int64 // 会话建立失败次数，含上游拨号/握手失败与目标不可达

	// 经该上游中继的有效载荷字节（TCP 流 + UDP 数据报，不含 SOCKS5 封装）：
	// bytesC2T 为客户端 -> 目标，bytesT2C 为目标 -> 客户端。
	bytesC2T atomic.Int64
	bytesT2C atomic.Int64

	// sessionsActive 为当前经该出口传输中的会话数（TCP CONNECT 隧道 +
	// UDP 上游会话），建立成功时 +1、会话关闭时 -1（closeOnce 保证恰好一次）。
	sessionsActive atomic.Int64

	// 主动健康检查探测（healthCheckLoop，区别于 fails 混合计入的被动流量
	// 反馈）：probeAttempts 为累计探测次数，probeFails 为其中探测失败次数，
	// 二者之差即探测成功次数，用于评估探测失败率与健康检查参数。
	probeAttempts atomic.Int64
	probeFails    atomic.Int64

	// 主动探测延迟：probeLastNS 为最近一次探测耗时（未探测过为 0），
	// probeSumNS 为累计耗时（配合 probeAttempts 可得平均耗时）；
	// probeLatencyBuckets 保存非累积的直方图观测桶，渲染 Prometheus 时
	// 再现场累加为累积桶，超过最大上界的观测只落入 +Inf。
	probeLastNS         atomic.Int64
	probeSumNS          atomic.Int64
	probeLatencyBuckets [len(probeLatencyUpperBounds)]atomic.Int64

	// 健康状态翻转累计（主动探测与被动流量反馈均计入）：markedDead 为
	// alive->dead 摘除次数，recovered 为 dead->alive 恢复次数；半开期间的
	// 重复失败不重新计数。两者持续增长可用于识别节点 flapping。
	markedDead atomic.Int64
	recovered  atomic.Int64

	// 被动流量反馈按失败阶段分类的累计次数（真实代理流量，不含主动探测）：
	// trafficFailsDial 为 TCP 拨号失败，trafficFailsHandshake 为 SOCKS5 握手/
	// 认证失败，trafficFailsWrite 为已建立会话的中继写入失败，
	// trafficFailsRequest 为拨号+握手成功后的 SOCKS5 请求阶段失败
	// （TCP CONNECT / UDP ASSOCIATE，含传输错误与上游回的目标不可达应答）；
	// request 阶段失败只计数、不参与健康摘除，因为健康上游也可能如实上报目标不可达。
	trafficFailsDial      atomic.Int64
	trafficFailsHandshake atomic.Int64
	trafficFailsWrite     atomic.Int64
	trafficFailsRequest   atomic.Int64
}

// 被动流量失败阶段标识，用于 reportUpstreamFailure 的分类计数。
const (
	trafficFailStageDial      = "dial"
	trafficFailStageHandshake = "handshake"
	trafficFailStageWrite     = "write"
	trafficFailStageRequest   = "request"
)

// trafficFailStages 为渲染观测端点时的固定阶段顺序。
var trafficFailStages = []string{
	trafficFailStageDial,
	trafficFailStageHandshake,
	trafficFailStageRequest,
	trafficFailStageWrite,
}

// upstreamHealthStates 为三态健康 gauge 的固定标签顺序，与
// upstreamHealth.state(now) 的取值一一对应。
var upstreamHealthStates = []string{"alive", "half_open", "dead"}

// probeLatencyUpperBounds 为主动探测延迟直方图的有限桶上界（秒），对齐
// Prometheus 默认延迟桶；超过最后一个上界的观测仅计入 +Inf 桶。
var probeLatencyUpperBounds = [...]float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

var gUpstreamHealth sync.Map // server -> *upstreamHealth

func getUpstreamHealth(server string) *upstreamHealth {
	if v, ok := gUpstreamHealth.Load(server); ok {
		return v.(*upstreamHealth)
	}
	h := &upstreamHealth{}
	h.alive.Store(true) // 未探测过的上游默认视为可用
	v, _ := gUpstreamHealth.LoadOrStore(server, h)
	return v.(*upstreamHealth)
}

// isAlive 报告上游当前是否可参与选路：正常存活，或摘除已满冷却进入半开状态
// （允许试探性放一个请求过去，成功则恢复、失败则重新计时）。
func (h *upstreamHealth) isAlive(now time.Time) bool {
	if h.alive.Load() {
		return true
	}
	deadAt := h.deadAt.Load()
	return deadAt != 0 && now.UnixNano()-deadAt >= gHealthCooldown.Load()
}

func isServerAlive(server string) bool {
	return getUpstreamHealth(server).isAlive(time.Now())
}

// state 返回三态健康状态：alive（存活）、half_open（已摘除但冷却期满，
// 可参与试探选路）、dead（摘除且仍在冷却窗口内）。
func (h *upstreamHealth) state(now time.Time) string {
	if h.alive.Load() {
		return "alive"
	}
	if h.isAlive(now) {
		return "half_open"
	}
	return "dead"
}

// recordFailure 记录一次失败（主动探测或真实流量反馈）。达到阈值即摘除；
// 半开期间再次失败则刷新摘除时刻、重新进入冷却。返回是否发生存活->摘除转换。
func (h *upstreamHealth) recordFailure(now time.Time) bool {
	becameDead := false
	if h.fails.Add(1) >= healthFailThreshold {
		if h.alive.Swap(false) {
			becameDead = true
			h.markedDead.Add(1)
		}
		h.deadAt.Store(now.UnixNano())
	}
	return becameDead
}

// recordSuccess 记录一次成功，清零失败计数并恢复存活，返回是否发生摘除->恢复转换。
func (h *upstreamHealth) recordSuccess() bool {
	h.fails.Store(0)
	if !h.alive.Swap(true) {
		h.recovered.Add(1)
		return true
	}
	return false
}

// reportUpstreamFailure 被动健康反馈：真实流量拨号/握手/写入上游失败时调用。
// stage 取 trafficFailStage* 之一，用于失败阶段分类计数；reason 仅用于日志。
func reportUpstreamFailure(server, stage, reason string) {
	h := getUpstreamHealth(server)
	switch stage {
	case trafficFailStageDial:
		h.trafficFailsDial.Add(1)
	case trafficFailStageHandshake:
		h.trafficFailsHandshake.Add(1)
	case trafficFailStageWrite:
		h.trafficFailsWrite.Add(1)
	}
	if h.recordFailure(time.Now()) {
		loggo.Info("upstream marked dead by traffic failure: %s (%s)", server, reason)
	}
}

// trafficFailCount 按阶段返回被动流量失败累计数，未知阶段返回 nil 桶（0）。
func (h *upstreamHealth) trafficFailCount(stage string) int64 {
	switch stage {
	case trafficFailStageDial:
		return h.trafficFailsDial.Load()
	case trafficFailStageHandshake:
		return h.trafficFailsHandshake.Load()
	case trafficFailStageRequest:
		return h.trafficFailsRequest.Load()
	case trafficFailStageWrite:
		return h.trafficFailsWrite.Load()
	default:
		return 0
	}
}

// reportUpstreamRequestFailure 记录一次 SOCKS5 请求阶段失败（TCP CONNECT /
// UDP ASSOCIATE 的请求帧写入/应答读取错误，或上游回的非 0 REP，例如目标不可达）。
// 只做失败阶段计数，不参与健康摘除：健康上游如实上报目标不可达不应被判定故障。
func reportUpstreamRequestFailure(server, reason string) {
	loggo.Info("upstream request-stage failure (not affecting health): %s (%s)", server, reason)
	getUpstreamHealth(server).trafficFailsRequest.Add(1)
}

// reportUpstreamSuccess 被动健康反馈：真实流量成功使用上游时调用，
// 可使半开重试中的上游立即恢复。
func reportUpstreamSuccess(server string) {
	if getUpstreamHealth(server).recordSuccess() {
		loggo.Info("upstream marked alive by traffic success: %s", server)
	}
}

// recordProbeLatency 记录一次主动探测的端到端耗时（TCP 连接 + SOCKS5 握手，
// 成功与失败均记录）：更新最近值、累计和，并给首个不小于耗时的桶 +1。
func (h *upstreamHealth) recordProbeLatency(d time.Duration) {
	ns := d.Nanoseconds()
	h.probeLastNS.Store(ns)
	h.probeSumNS.Add(ns)
	secs := float64(ns) / float64(time.Second)
	for i, upperBound := range probeLatencyUpperBounds {
		if secs <= upperBound {
			h.probeLatencyBuckets[i].Add(1)
			return
		}
	}
	// 超过最大有限桶上界：仅计入渲染时的 +Inf 桶
}

// probeAvgMS 返回累计平均主动探测耗时（毫秒）；尚无探测时为 0。
func probeAvgMS(h *upstreamHealth) float64 {
	n := h.probeAttempts.Load()
	if n == 0 {
		return 0
	}
	return float64(h.probeSumNS.Load()) / 1e6 / float64(n)
}

// probeUpstream 对上游做一次探测：TCP 连接 + SOCKS5 客户端握手（含账密认证）。
func probeUpstream(server string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("probe upstream %s: unexpected conn type %T", server, conn)
	}
	return network.Sock5Handshake(tcpConn, int(timeout/time.Millisecond), *susername, *spassword)
}

// checkUpstream 探测单个上游并更新健康状态，返回探测是否成功。
// 连续 healthFailThreshold 次失败判定为不可用，一次成功即恢复。
func checkUpstream(server string, timeout time.Duration) bool {
	h := getUpstreamHealth(server)
	h.probeAttempts.Add(1)
	start := time.Now()
	defer func() { h.recordProbeLatency(time.Since(start)) }()
	if err := probeUpstream(server, timeout); err != nil {
		h.probeFails.Add(1)
		if h.recordFailure(time.Now()) {
			loggo.Info("upstream health check dead: %s err %s", server, err)
		}
		return false
	}
	if h.recordSuccess() {
		loggo.Info("upstream health check alive: %s", server)
	}
	return true
}

// filterAliveServers 过滤掉健康检查判定为不可用的上游；全部不可用时保留原列表，
// 由按需 failover 兜底，避免健康检查误判导致完全拒绝服务。
func filterAliveServers(candidates []string) []string {
	filtered := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if isServerAlive(c) {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 {
		return candidates
	}
	return filtered
}

func probeAllUpstreams(timeout time.Duration) {
	for _, s := range strings.Fields(*servers) {
		go checkUpstream(s, timeout)
	}
}

func healthCheckLoop(interval, timeout time.Duration) {
	probeAllUpstreams(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		probeAllUpstreams(timeout)
	}
}

func getOutboundIPFor(dst net.IP) net.IP {
	if dst == nil {
		return nil
	}
	networkStr := "udp4"
	if dst.To4() == nil {
		networkStr = "udp6"
	}
	dummyConn, err := net.Dial(networkStr, net.JoinHostPort(dst.String(), "1"))
	if err != nil {
		return nil
	}
	defer dummyConn.Close()
	return dummyConn.LocalAddr().(*net.UDPAddr).IP
}

// dialTCPTimeout 在限定时间内建立 TCP 连接，避免黑洞节点（防火墙丢包而非拒连）
// 让拨号阻塞到操作系统默认超时（通常约 75s），保证 failover 能快速生效。
func dialTCPTimeout(addr string, timeout time.Duration) (*net.TCPConn, error) {
	return dialTCPTimeoutCtx(context.Background(), addr, timeout)
}

// dialTCPTimeoutCtx 同 dialTCPTimeout，但额外受 ctx 约束：优雅关闭强制断开时，
// 进行中的拨号也会立即失败，不必等到拨号超时。
func dialTCPTimeoutCtx(ctx context.Context, addr string, timeout time.Duration) (*net.TCPConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s: unexpected conn type %T", addr, conn)
	}
	enableTCPKeepAlive(tcpConn)
	return tcpConn, nil
}

// dialTimeout 返回配置的拨号超时；非法（<=0）配置回退到 10s 默认值。
func dialTimeout() time.Duration {
	if *dialTimeoutSec > 0 {
		return time.Duration(*dialTimeoutSec) * time.Second
	}
	return 10 * time.Second
}

// relayIdleTimeout 返回 relay 连接的双向空闲超时；0 表示关闭（保持长连接永不主动断开）。
func relayIdleTimeout() time.Duration {
	if *idleTimeoutSec > 0 {
		return time.Duration(*idleTimeoutSec) * time.Second
	}
	return 0
}

// udpIdleTimeout 返回 UDP 关联的空闲超时；0 表示关闭。
// UDP 关联仅靠客户端关闭控制 TCP 释放，客户端异常掉线（半开无 FIN）时
// 会泄漏 relay UDP 套接字、直连套接字与上游会话，需要空闲回收兜底。
func udpIdleTimeout() time.Duration {
	if *udpIdleTimeoutSec > 0 {
		return time.Duration(*udpIdleTimeoutSec) * time.Second
	}
	return 0
}

// tcpKeepaliveIdle 返回 TCP keepalive 的空闲时长；0 表示关闭。
func tcpKeepaliveIdle() time.Duration {
	if *tcpKeepaliveSec > 0 {
		return time.Duration(*tcpKeepaliveSec) * time.Second
	}
	return 0
}

// admitSession 在 SOCKS5 握手与请求解析完成后做并发会话准入。
// -max-conn<=0 时不限；否则当前已接受连接数（含自身，握手在途也占名额，
// 口径偏保守）超过上限即拒绝，并累计拒绝计数。
// 计数在 serve 接受连接时同步自增，因此并发准入判断不会突破硬上限。
func admitSession() bool {
	limit := int64(*maxConn)
	if limit <= 0 {
		return true
	}
	if gActiveTCPConns.Load() > limit {
		gRejectedConns.Add(1)
		return false
	}
	return true
}

// enableTCPKeepAlive 在连接上启用 SO_KEEPALIVE，让内核探测半开连接
// （对端断电/断网无 FIN），探测失败后 Read/Write 返回错误，连接得以释放。
// 与应用层 -idle-timeout 的区别：keepalive 只在完全无数据时由内核发探测包，
// 不主动关闭空闲但健康的长连接，是传输层兜底。
// 任何平台相关的设置失败都不得中断连接处理，逐级回退到最基础的保活开关。
func enableTCPKeepAlive(conn *net.TCPConn) {
	if conn == nil {
		return
	}
	idle := tcpKeepaliveIdle()
	if idle <= 0 {
		// Go 的零值 net.Dialer 默认会为拨出连接开启 keepalive（当前为 15s），
		// 配置为关闭时必须显式关掉，才能让上游/直连拨出连接真正回到系统默认。
		if err := conn.SetKeepAlive(false); err != nil {
			loggo.Debug("disable tcp keepalive fail: %s", err)
		}
		return
	}
	// 探测间隔取 idle/3（至少 1s），连续 3 次无应答判定死亡，
	// 最坏情况下约 idle+3*interval 检测到半开。
	interval := idle / 3
	if interval < time.Second {
		interval = time.Second
	}
	cfg := net.KeepAliveConfig{
		Enable:   true,
		Idle:     idle,
		Interval: interval,
		Count:    3,
	}
	if err := conn.SetKeepAliveConfig(cfg); err == nil {
		return
	}
	// 老内核/平台不支持精细参数时回退：仅开关 + 统一周期
	if err := conn.SetKeepAlive(true); err != nil {
		loggo.Debug("enable tcp keepalive fail: %s", err)
		return
	}
	_ = conn.SetKeepAlivePeriod(idle)
}

// idleTimeoutReader 包装 relay 一端的读操作：每次 Read 前刷新读 deadline，
// 并把本方向成功读到数据的时刻写入共享的 lastActivity。任一方向仍有流量时，
// 另一方向即使自身读超时也会续命继续等待，避免误伤单向有数据的下载类长连接。
// 只有两个方向都静默超过 idle 后，Read 才真正返回 i/o timeout 触发关连。
type idleTimeoutReader struct {
	conn         *net.TCPConn
	idle         time.Duration
	lastActivity *atomic.Int64 // 最近一次任一方向读到数据的 unix nano
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	for {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.idle))
		n, err := r.conn.Read(p)
		if n > 0 {
			r.lastActivity.Store(time.Now().UnixNano())
			// 可能同时返回 EOF：先把数据交给 io.Copy，下一次 Read 再透传 EOF。
			return n, err
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				last := time.Unix(0, r.lastActivity.Load())
				if time.Since(last) < r.idle {
					// 对向刚有流量，整条隧道并非空闲，进入下一轮等待。
					continue
				}
			}
		}
		return n, err
	}
}

func process(ctx context.Context, conn *net.TCPConn) {
	defer common.CrashLog()
	defer conn.Close()

	var err error = nil
	if err = network.Sock5HandshakeBy(conn, *username, *password); err != nil {
		loggo.Error("process socks handshake: %s", err)
		gEntryErrHandshake.Add(1)
		return
	}
	cmd, _, targetAddr, err := network.Sock5GetRequest(conn)
	if err != nil {
		// gohome 的请求解析会直接拒绝 CONNECT/UDP-ASSOCIATE 以外的命令
		//（错误文本 "socks command not supported"，版本锁定在 go.mod）：
		// 与帧不完整/版本错误等畸形请求区分开，并按 RFC 回 0x07 命令不支持，
		// 而不是让客户端只看到连接重置。
		if strings.Contains(err.Error(), "command not supported") {
			loggo.Error("process unsupported socks command in request: %s", err)
			gEntryErrUnsupportedCmd.Add(1)
			_ = network.Sock5SendConnectReply(conn, 0x07, "0.0.0.0:0")
		} else {
			loggo.Error("process error getting request: %s", err)
			gEntryErrBadRequest.Add(1)
		}
		return
	}

	// 并发会话上限：握手与请求解析完成后才拒绝，便于回合法 SOCKS5 失败应答，
	// 客户端无需把裸 TCP 关闭误判为网络错误。
	if !admitSession() {
		loggo.Info("process reject socks session, max-conn=%d reached: client=%s", *maxConn, conn.RemoteAddr())
		_ = network.Sock5SendConnectReply(conn, 0x01, "0.0.0.0:0")
		return
	}

	if cmd == network.Socks5CmdConnect {
		// Sending connection established message immediately to client.
		// This saves some round trip time for creating socks connection with the client.
		// But if connection failed, the client will get connection reset error.
		_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
		if err != nil {
			loggo.Error("process send connection confirmation: %s", err)
			return
		}

		loggo.Info("process accept new sock5 conn: %s", targetAddr)

		if need_proxy(targetAddr) {
			process_proxy(ctx, conn, targetAddr)
		} else {
			process_direct(ctx, conn, targetAddr)
		}
	} else if cmd == network.Socks5CmdUDPAssociate {
		process_udp(ctx, conn, targetAddr)
	} else {
		loggo.Error("process unsupported socks command: %d", cmd)
		gEntryErrUnsupportedCmd.Add(1)
		_ = network.Sock5SendConnectReply(conn, 0x07, "0.0.0.0:0")
	}
}

type udpUpstreamSession struct {
	server        string
	proxyTCPConn  *net.TCPConn
	proxyUDPConn  *net.UDPConn
	upstreamRelay *net.UDPAddr
	closeOnce     sync.Once
}

func (s *udpUpstreamSession) close() {
	s.closeOnce.Do(func() {
		// 与 getOrCreateUpstreamSession 建立成功时的 +1 配对，
		// closeOnce 保证 removeUpstreamSession 与 assoc.close 两条路径只减一次。
		getUpstreamHealth(s.server).sessionsActive.Add(-1)
		if s.proxyTCPConn != nil {
			_ = s.proxyTCPConn.Close()
		}
		if s.proxyUDPConn != nil {
			_ = s.proxyUDPConn.Close()
		}
	})
}

type udpAssociation struct {
	clientTCPConn       *net.TCPConn
	clientTCPRemoteAddr *net.TCPAddr

	clientExpectedIP net.IP
	clientRelayConn  *net.UDPConn

	// drainCtx 在优雅关闭排空窗口结束时取消，使进行中的上游拨号立即失败。
	drainCtx context.Context

	// lastActivity 记录最近一次任一方向收到 UDP 包的时刻（unix nano），
	// 供 -udp-idle-timeout 回收僵尸关联；多个收包 goroutine 并发原子读写。
	lastActivity atomic.Int64

	activeClientUDPAddr atomic.Pointer[net.UDPAddr]
	closed              atomic.Bool
	relayWg             sync.WaitGroup // 跟踪 runClientRelay 读循环
	packetWg            sync.WaitGroup // 跟踪每个数据包的处理 goroutine

	directMu   sync.Mutex
	directConn *net.UDPConn

	upstreamMu       sync.Mutex
	upstreamSessions map[string]*udpUpstreamSession

	// targetServers 记录每个目标地址当前绑定的上游，保证同一目标的 UDP 包
	// 始终走同一上游（维持上游 relay 的目标映射/NAT 一致性），仅在故障时切换。
	targetMu      sync.Mutex
	targetServers map[string]string
}

func (assoc *udpAssociation) close() {
	if assoc.closed.CompareAndSwap(false, true) {
		// 先关闭客户端 relay 套接字并等待读循环退出。runClientRelay 是
		// packetWg 的唯一 Add 方，必须等它退出后再 Wait，避免 Add/Wait 竞态。
		if assoc.clientRelayConn != nil {
			_ = assoc.clientRelayConn.Close()
		}
		assoc.relayWg.Wait()

		assoc.directMu.Lock()
		if assoc.directConn != nil {
			_ = assoc.directConn.Close()
			gRouteSessionsActiveDirect.Add(-1)
		}
		assoc.directMu.Unlock()

		assoc.upstreamMu.Lock()
		for _, s := range assoc.upstreamSessions {
			s.close()
		}
		assoc.upstreamSessions = make(map[string]*udpUpstreamSession)
		assoc.upstreamMu.Unlock()

		assoc.targetMu.Lock()
		assoc.targetServers = make(map[string]string)
		assoc.targetMu.Unlock()

		assoc.packetWg.Wait()
	}
}

func (assoc *udpAssociation) runClientRelay() {
	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := assoc.clientRelayConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if assoc.closed.Load() {
			return
		}
		assoc.lastActivity.Store(time.Now().UnixNano())

		if !srcAddr.IP.Equal(assoc.clientExpectedIP) {
			loggo.Debug("udp drop packet from unexpected source: %s, expected: %s", srcAddr, assoc.clientExpectedIP)
			continue
		}

		assoc.activeClientUDPAddr.Store(srcAddr)

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		assoc.packetWg.Add(1)
		go func(p []byte) {
			defer assoc.packetWg.Done()
			assoc.handlePacket(p)
		}(pkt)
	}
}

func (assoc *udpAssociation) handlePacket(pkt []byte) {
	if assoc.closed.Load() {
		return
	}

	host, port, data, err := network.Sock5UnpackUDP(pkt)
	if err != nil {
		loggo.Debug("udp Sock5UnpackUDP error: %s", err)
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	loggo.Debug("udp receive packet for target %s from client %s (data len %d)", targetAddr, assoc.clientTCPRemoteAddr, len(data))

	if need_proxy(targetAddr) {
		// len(data) 为去除 SOCKS5 UDP 封装后的有效载荷长度，用于按出口字节归因。
		assoc.handleProxyPacket(targetAddr, pkt, len(data))
	} else {
		assoc.handleDirectPacket(targetAddr, host, port, data)
	}
}

func (assoc *udpAssociation) handleDirectPacket(targetAddr string, host string, port int, data []byte) {
	dConn, err := assoc.getOrCreateDirectConn()
	if err != nil {
		loggo.Info("udp getOrCreateDirectConn fail: %s", err)
		return
	}

	resolvedHost := host
	if !common.IsValidIP(host) {
		// 与 need_proxy 使用同一套解析/缓存，确保分流判定的 IP 与实际拨号 IP 一致
		rootHost, err := common.GetRootDomain(targetAddr)
		if err == nil {
			if ip, ok := resolveRouteIP(host, rootHost); ok {
				resolvedHost = ip
			}
		}
	}

	targetResolvedAddr := net.JoinHostPort(resolvedHost, strconv.Itoa(port))
	udpTarget, err := net.ResolveUDPAddr("udp", targetResolvedAddr)
	if err != nil {
		loggo.Info("udp direct ResolveUDPAddr error: %s %s", targetResolvedAddr, err)
		return
	}

	_, err = dConn.WriteToUDP(data, udpTarget)
	if err != nil {
		loggo.Info("udp direct WriteToUDP error: %s %s", targetResolvedAddr, err)
		return
	}
	// 直连出口客户端 -> 目标有效载荷字节（data 已去除 SOCKS5 封装）。
	gRouteBytesDirectC2T.Add(int64(len(data)))
}

func (assoc *udpAssociation) getOrCreateDirectConn() (*net.UDPConn, error) {
	assoc.directMu.Lock()
	defer assoc.directMu.Unlock()

	if assoc.closed.Load() {
		return nil, errors.New("association closed")
	}
	if assoc.directConn != nil {
		return assoc.directConn, nil
	}

	dConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	assoc.directConn = dConn
	// UDP 直连套接字建立成功即计入 direct 出口会话；assoc.close 关闭它时配对 -1。
	gRouteSessionsTotalDirect.Add(1)
	gRouteSessionsActiveDirect.Add(1)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, remoteAddr, err := dConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if assoc.closed.Load() {
				return
			}
			assoc.lastActivity.Store(time.Now().UnixNano())
			// 直连出口目标 -> 客户端有效载荷字节（目标返回的裸 UDP 数据报）。
			gRouteBytesDirectT2C.Add(int64(n))
			clientAddr := assoc.activeClientUDPAddr.Load()
			if clientAddr == nil {
				continue
			}
			respPkt, err := network.Sock5PackUDP(remoteAddr.IP.String(), remoteAddr.Port, buf[:n])
			if err != nil {
				continue
			}
			_, _ = assoc.clientRelayConn.WriteToUDP(respPkt, clientAddr)
		}
	}()

	return assoc.directConn, nil
}

// pinTargetServer 返回目标当前绑定的上游；首次调用时绑定为 candidates[0]。
func (assoc *udpAssociation) pinTargetServer(targetAddr string, candidates []string) string {
	assoc.targetMu.Lock()
	defer assoc.targetMu.Unlock()
	if server, ok := assoc.targetServers[targetAddr]; ok {
		return server
	}
	server := candidates[0]
	assoc.targetServers[targetAddr] = server
	return server
}

// setPinTargetServer 无条件把目标绑定到指定上游（failover 成功后调用）。
func (assoc *udpAssociation) setPinTargetServer(targetAddr, server string) {
	assoc.targetMu.Lock()
	defer assoc.targetMu.Unlock()
	assoc.targetServers[targetAddr] = server
}

// unpinTargetServer 清除所有指向该上游的目标绑定。
func (assoc *udpAssociation) unpinTargetServer(server string) {
	assoc.targetMu.Lock()
	defer assoc.targetMu.Unlock()
	for target, s := range assoc.targetServers {
		if s == server {
			delete(assoc.targetServers, target)
		}
	}
}

func (assoc *udpAssociation) handleProxyPacket(targetAddr string, pkt []byte, payloadLen int) {
	candidates := getCandidateServers(targetAddr, assoc.clientTCPRemoteAddr.IP.String(), assoc.clientTCPRemoteAddr.String())
	if len(candidates) == 0 {
		loggo.Error("udp handleProxyPacket no servers fail: %s", targetAddr)
		return
	}

	// 已绑定的上游优先尝试，失败后再按候选顺序 failover，保证同目标粘性。
	pinned, ordered := targetCandidateOrder(assoc, targetAddr, candidates)

	for _, server := range ordered {
		session, err := assoc.getOrCreateUpstreamSession(server)
		if err != nil {
			loggo.Info("udp getOrCreateUpstreamSession fail: %s %s", server, err)
			assoc.unpinTargetServer(server)
			continue
		}
		_, err = session.proxyUDPConn.WriteToUDP(pkt, session.upstreamRelay)
		if err != nil {
			loggo.Info("udp WriteToUDP to upstream %s fail: %s", server, err)
			reportUpstreamFailure(server, trafficFailStageWrite, "udp relay write: "+err.Error())
			assoc.removeUpstreamSession(server)
			continue
		}
		// 发送成功：绑定（或故障后改绑）到该可用上游，后续包保持粘性
		reportUpstreamSuccess(server)
		// 经该上游客户端 -> 目标的有效载荷字节（按解包后的 payload 计，不含封装头）。
		getUpstreamHealth(server).bytesC2T.Add(int64(payloadLen))
		if server != pinned {
			assoc.setPinTargetServer(targetAddr, server)
		}
		return
	}
	loggo.Info("udp handleProxyPacket no valid servers: %s", targetAddr)
}

// targetCandidateOrder 返回以绑定上游为首、其余候选去重跟随的尝试顺序；
// 尚未绑定时绑定 candidates[0]。绑定上游若已被健康检查摘除出候选列表，
// 则改绑为当前首选，避免继续向已知故障节点发包。
func targetCandidateOrder(assoc *udpAssociation, targetAddr string, candidates []string) (string, []string) {
	pinned := assoc.pinTargetServer(targetAddr, candidates)
	if !slices.Contains(candidates, pinned) {
		pinned = candidates[0]
		assoc.setPinTargetServer(targetAddr, pinned)
	}
	ordered := make([]string, 0, len(candidates))
	ordered = append(ordered, pinned)
	for _, c := range candidates {
		if c != pinned {
			ordered = append(ordered, c)
		}
	}
	return pinned, ordered
}

func (assoc *udpAssociation) getOrCreateUpstreamSession(server string) (*udpUpstreamSession, error) {
	assoc.upstreamMu.Lock()
	defer assoc.upstreamMu.Unlock()

	if assoc.closed.Load() {
		return nil, errors.New("association closed")
	}

	if sess, ok := assoc.upstreamSessions[server]; ok {
		// 复用已有上游会话：不计入新的会话建立尝试。
		return sess, nil
	}

	h := getUpstreamHealth(server)
	h.attempts.Add(1)
	created := false
	defer func() {
		if !created {
			h.connectFails.Add(1)
		}
	}()

	proxyTCPConn, err := dialTCPTimeoutCtx(assoc.drainCtx, server, dialTimeout())
	if err != nil {
		reportUpstreamFailure(server, trafficFailStageDial, "udp tcp dial: "+err.Error())
		return nil, err
	}

	err = network.Sock5Handshake(proxyTCPConn, 5000, *susername, *spassword)
	if err != nil {
		_ = proxyTCPConn.Close()
		reportUpstreamFailure(server, trafficFailStageHandshake, "udp socks5 handshake: "+err.Error())
		return nil, err
	}

	bnd, err := network.Sock5SetUDPRequest(proxyTCPConn, "0.0.0.0", 0, 5000)
	if err != nil {
		_ = proxyTCPConn.Close()
		reportUpstreamRequestFailure(server, "udp associate request: "+err.Error())
		return nil, err
	}

	bndHost, bndPortStr, err := net.SplitHostPort(bnd)
	if err != nil {
		_ = proxyTCPConn.Close()
		return nil, err
	}
	bndPort, err := strconv.Atoi(bndPortStr)
	if err != nil {
		_ = proxyTCPConn.Close()
		return nil, err
	}
	bndIP := net.ParseIP(bndHost)
	if bndIP == nil {
		resolved, rErr := net.ResolveIPAddr("ip", bndHost)
		if rErr == nil && resolved != nil {
			bndIP = resolved.IP
		}
	}
	if bndIP == nil || bndIP.IsUnspecified() {
		bndIP = proxyTCPConn.RemoteAddr().(*net.TCPAddr).IP
	}
	relayUDPAddr := &net.UDPAddr{IP: bndIP, Port: bndPort}

	proxyUDPConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = proxyTCPConn.Close()
		return nil, err
	}

	session := &udpUpstreamSession{
		server:        server,
		proxyTCPConn:  proxyTCPConn,
		proxyUDPConn:  proxyUDPConn,
		upstreamRelay: relayUDPAddr,
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := proxyUDPConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if assoc.closed.Load() {
				return
			}
			assoc.lastActivity.Store(time.Now().UnixNano())
			// 上游回包为 SOCKS5 UDP 封装帧，按解包后的有效载荷计入目标 -> 客户端；
			// 解包失败的畸形帧仍透传给客户端，但不参与字节归因。
			if _, _, data, uerr := network.Sock5UnpackUDP(buf[:n]); uerr == nil {
				h.bytesT2C.Add(int64(len(data)))
			}
			clientAddr := assoc.activeClientUDPAddr.Load()
			if clientAddr == nil {
				continue
			}
			_, _ = assoc.clientRelayConn.WriteToUDP(buf[:n], clientAddr)
		}
	}()

	go func() {
		dummy := make([]byte, 1)
		for {
			_, err := proxyTCPConn.Read(dummy)
			if err != nil {
				session.close()
				assoc.removeUpstreamSession(server)
				return
			}
		}
	}()

	assoc.upstreamSessions[server] = session
	// 会话建立成功瞬间入账；后续包复用该会话不再计数。
	h.established.Add(1)
	h.sessionsActive.Add(1) // 与 session.close() 的 -1 配对
	created = true
	loggo.Info("udp established upstream session to %s (relay %s) for client %s", server, relayUDPAddr, assoc.clientTCPRemoteAddr)
	return session, nil
}

func (assoc *udpAssociation) removeUpstreamSession(server string) {
	assoc.upstreamMu.Lock()
	if sess, ok := assoc.upstreamSessions[server]; ok {
		sess.close()
		delete(assoc.upstreamSessions, server)
	}
	assoc.upstreamMu.Unlock()
	// 会话失效后解除指向该上游的目标绑定，使下一个包重新选择
	assoc.unpinTargetServer(server)
}

func process_udp(ctx context.Context, conn *net.TCPConn, targetAddr string) {
	defer common.CrashLog()

	localTCPAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteTCPAddr := conn.RemoteAddr().(*net.TCPAddr)

	bndIP := localTCPAddr.IP
	if bndIP == nil || bndIP.IsUnspecified() {
		if remoteTCPAddr.IP.IsLoopback() {
			if remoteTCPAddr.IP.To4() != nil {
				bndIP = net.IPv4(127, 0, 0, 1)
			} else {
				bndIP = net.IPv6loopback
			}
		} else if outIP := getOutboundIPFor(remoteTCPAddr.IP); outIP != nil {
			bndIP = outIP
		} else {
			bndIP = net.IPv4(127, 0, 0, 1)
		}
	}

	clientRelayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bndIP, Port: 0})
	if err != nil {
		clientRelayConn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			loggo.Error("process_udp ListenUDP fail: %s", err)
			_ = network.Sock5SendConnectReply(conn, 0x01, "0.0.0.0:0")
			return
		}
	}

	relayUDPAddr := clientRelayConn.LocalAddr().(*net.UDPAddr)
	bndAddr := net.JoinHostPort(bndIP.String(), strconv.Itoa(relayUDPAddr.Port))

	err = network.Sock5SendConnectReply(conn, 0x00, bndAddr)
	if err != nil {
		loggo.Error("process_udp Sock5SendConnectReply fail: %s", err)
		_ = clientRelayConn.Close()
		return
	}

	loggo.Info("process_udp accept new sock5 udp associate: client=%s bnd=%s", remoteTCPAddr, bndAddr)

	gActiveUDPAssoc.Add(1)
	gTotalUDPAssoc.Add(1)
	defer gActiveUDPAssoc.Add(-1)

	assoc := &udpAssociation{
		clientTCPConn:       conn,
		clientTCPRemoteAddr: remoteTCPAddr,
		clientExpectedIP:    remoteTCPAddr.IP,
		clientRelayConn:     clientRelayConn,
		drainCtx:            ctx,
		upstreamSessions:    make(map[string]*udpUpstreamSession),
		targetServers:       make(map[string]string),
	}
	assoc.lastActivity.Store(time.Now().UnixNano())

	if targetHost, targetPortStr, err := net.SplitHostPort(targetAddr); err == nil {
		if targetPort, err := strconv.Atoi(targetPortStr); err == nil && targetPort > 0 {
			targetIP := net.ParseIP(targetHost)
			if targetIP != nil && !targetIP.IsUnspecified() {
				assoc.activeClientUDPAddr.Store(&net.UDPAddr{IP: targetIP, Port: targetPort})
			}
		}
	}

	defer assoc.close()

	assoc.relayWg.Add(1)
	go func() {
		defer assoc.relayWg.Done()
		assoc.runClientRelay()
	}()

	done := make(chan struct{})
	defer close(done)

	// 空闲回收：定期检查最近收包时刻，双向静默超过 idle 则关闭控制连接，
	// 主 Read 循环随之退出并走 assoc.close() 释放 relay/直连/上游全部资源。
	idle := udpIdleTimeout()
	var idleCh <-chan time.Time
	if idle > 0 {
		interval := idle / 4
		if interval < 200*time.Millisecond {
			interval = 200 * time.Millisecond
		}
		if interval > 30*time.Second {
			interval = 30 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		idleCh = ticker.C
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-idleCh:
				last := time.Unix(0, assoc.lastActivity.Load())
				if time.Since(last) >= idle {
					loggo.Info("udp association idle for %s, closing: client=%s", idle, remoteTCPAddr)
					// reaper 关连后立即退出，每条关联在本分支恰好计数一次。
					gIdleClosedUDP.Add(1)
					_ = conn.Close()
					return
				}
			case <-done:
				return
			}
		}
	}()

	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	loggo.Info("process_udp client tcp closed, terminating association: client=%s", remoteTCPAddr)
}

func process_proxy_server(ctx context.Context, conn *net.TCPConn, targetAddr string, server string) bool {
	h := getUpstreamHealth(server)
	h.attempts.Add(1)
	// 任一提前返回都计一次建立失败；成功路径在 Sock5SetRequest 通过后置 established 标志。
	established := false
	defer func() {
		if !established {
			h.connectFails.Add(1)
		}
	}()

	proxyconn, err := dialTCPTimeoutCtx(ctx, server, dialTimeout())
	if err != nil {
		loggo.Info("process_proxy_server tcp DialTCP fail: %s %s", targetAddr, err.Error())
		reportUpstreamFailure(server, trafficFailStageDial, "tcp dial: "+err.Error())
		return false
	}
	defer proxyconn.Close()

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	err = network.Sock5Handshake(proxyconn, 0, *susername, *spassword)
	if err != nil {
		loggo.Info("process_proxy_server Sock5Handshake fail: %s %s", targetAddr, err.Error())
		reportUpstreamFailure(server, trafficFailStageHandshake, "socks5 handshake: "+err.Error())
		return false
	}
	// 拨号+握手成功即证明上游可用：清零被动失败计数，并使半开节点立即恢复
	reportUpstreamSuccess(server)

	dsthost, dstportstr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		loggo.Info("process_proxy_server SplitHostPort error: %s", err)
		return false
	}

	dstport, err := strconv.Atoi(dstportstr)
	if err != nil {
		loggo.Info("process_proxy_server Atoi error: %s", err)
		return false
	}

	err = network.Sock5SetRequest(proxyconn, dsthost, dstport, 0)
	if err != nil {
		loggo.Info("process_proxy_server Sock5SetRequest fail: %s %s", targetAddr, err.Error())
		reportUpstreamRequestFailure(server, "connect request: "+err.Error())
		return false
	}

	// 会话已建立：成功瞬间入账，随后 relay 即使中断也不改写该口径。
	h.established.Add(1)
	established = true
	// 经该上游的活跃 TCP 隧道 +1，relay 返回、本函数退出时配对 -1。
	h.sessionsActive.Add(1)
	defer h.sessionsActive.Add(-1)

	loggo.Info("client accept new proxy local tcp %s %s %s", server, tcpsrcaddr.String(), targetAddr)

	if relay(ctx, conn, proxyconn, &h.bytesC2T, &h.bytesT2C) {
		gIdleClosedTCP.Add(1)
	}

	return true
}

func process_proxy(ctx context.Context, conn *net.TCPConn, targetAddr string) {
	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)
	candidates := getCandidateServers(targetAddr, tcpsrcaddr.IP.String(), tcpsrcaddr.String())
	if len(candidates) == 0 {
		loggo.Error("process_proxy no servers fail: %s", targetAddr)
		return
	}
	for _, server := range candidates {
		if process_proxy_server(ctx, conn, targetAddr, server) {
			return
		}
	}
	loggo.Info("process_proxy no valid servers fail: %s", *servers)
}

func process_direct(ctx context.Context, conn *net.TCPConn, targetAddr string) {
	// 直连目标同样受 -dial-timeout 约束，避免黑洞目标长时间占用 goroutine。
	// 注意：直连失败不调用 reportUpstreamFailure，目标不可达不属于上游故障。
	targetconn, err := dialTCPTimeoutCtx(ctx, targetAddr, dialTimeout())
	if err != nil {
		loggo.Info("process_direct tcp dial fail: %s %s", targetAddr, err.Error())
		return
	}
	defer targetconn.Close()

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	loggo.Info("process_direct client accept new direct local tcp %s %s", tcpsrcaddr.String(), targetAddr)

	// 直连拨号成功即视为 direct 出口会话建立；relay 返回时活跃数 -1。
	gRouteSessionsTotalDirect.Add(1)
	gRouteSessionsActiveDirect.Add(1)
	defer gRouteSessionsActiveDirect.Add(-1)

	if relay(ctx, conn, targetconn, &gRouteBytesDirectC2T, &gRouteBytesDirectT2C) {
		gIdleClosedTCP.Add(1)
	}
}

// relay 双向转发直到任一端关闭。返回值 idleClosed 表示隧道是因双向静默超过
// -idle-timeout 被本端主动回收（i/o timeout），而非对端正常关闭或排空期强制断开；
// 两个方向即使同时报 timeout，对调用方也只计一次。
func relay(ctx context.Context, c1, c2 *net.TCPConn, routeC2T, routeT2C *atomic.Int64) (idleClosed bool) {
	var closeOnce sync.Once
	closeBoth := func() {
		_ = c1.Close()
		_ = c2.Close()
	}

	// 优雅关闭排空窗口结束后 ctx 取消，强制断开仍在传输的两端。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeOnce.Do(closeBoth)
		case <-done:
		}
	}()

	// 两个转发方向共享同一份活跃时间：任一方向读到数据都为整条隧道续命。
	var lastActivity atomic.Int64
	idle := relayIdleTimeout()

	errCh := make(chan error, 2)
	// c1 为客户端连接、c2 为目标（直连或上游）连接，分别累计两个方向的中继字节。
	// 全局口径（仅 TCP）与按出口归因口径（TCP+UDP 共用同一组路由计数器）同时入账。
	go proxy(c1, c2, c1.RemoteAddr().String(), c2.RemoteAddr().String(), errCh, idle, &lastActivity, &gBytesClientToTarget, routeC2T)
	go proxy(c2, c1, c2.RemoteAddr().String(), c1.RemoteAddr().String(), errCh, idle, &lastActivity, &gBytesTargetToClient, routeT2C)

	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil && err != io.EOF {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// idleTimeoutReader 的双向静默判定超时（普通读 deadline 不会设置）。
				idleClosed = true
			}
			closeOnce.Do(closeBoth)
		}
	}
	closeOnce.Do(closeBoth)
	return idleClosed
}

func proxy(destination *net.TCPConn, source *net.TCPConn, dst string, src string, errCh chan error, idle time.Duration, lastActivity *atomic.Int64, byteCounter *atomic.Int64, routeCounter *atomic.Int64) {
	loggo.Debug("transfer client begin transfer from %s -> %s", src, dst)
	var reader io.Reader = source
	if idle > 0 {
		reader = &idleTimeoutReader{conn: source, idle: idle, lastActivity: lastActivity}
	}
	n, err := io.Copy(destination, reader)
	if byteCounter != nil {
		byteCounter.Add(n)
	}
	if routeCounter != nil {
		routeCounter.Add(n)
	}
	_ = destination.CloseWrite()
	errCh <- err
	loggo.Debug("transfer client end transfer from %s -> %s %v %v", src, dst, n, err)
}
