package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"runtime"
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
	version = "0.5.0"

	listen       = flag.String("l", ":1080", "listen addr")
	servers      = flag.String("s", "server1 server2 server3", "server addr")
	sel          = flag.String("select", "robin", "select server robin/rand/hash_by_dst_ip/hash_by_src_ip/hash_all")
	skip         = flag.String("skip", "CN", "skip country")
	filename     = flag.String("file", "GeoLite2-Country.mmdb", "ip file")
	chinaDomains = flag.String("china_domains", "accelerated-domains.china.conf", "china domains file")
	cache_size   = flag.Int("cache_size", 1000, "cache size for dns")
	cache_expire = flag.Int("cache_expire", 3600, "cache expire seconds for dns")
	loglevel     = flag.String("loglevel", "info", "log level")
	nolog        = flag.Int("nolog", 0, "write log file")
	noprint      = flag.Int("noprint", 0, "print stdout")
	username     = flag.String("username", "", "username")
	password     = flag.String("password", "", "password")
	showVersion  = flag.Bool("version", false, "show version and exit")
)

var (
	gResolver     dns.Resolver
	gDnsCache     *lru.LRUMultiCache[string, string]
	gChinaDomains map[string]bool
	gRobinIndex   atomic.Uint64
)

func main() {
	flag.Parse()

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

	init_env()

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		loggo.Info("received shutdown signal, stopping listener...")
		_ = tcplistenConn.Close()
	}()

	for {
		conn, err := tcplistenConn.AcceptTCP()
		if err != nil {
			select {
			case <-ctx.Done():
				loggo.Info("listener closed, exiting...")
				return
			default:
				loggo.Info("Error accept tcp %s", err)
				continue
			}
		}

		go process(ctx, conn)
	}
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

	// 优先直接使用 gResolver 的快速分流判断
	if gResolver != nil {
		if shouldProxy, err := gResolver.ShouldProxy(host); err == nil {
			loggo.Info("need_proxy by gResolver: %s proxy=%v", host, shouldProxy)
			return shouldProxy
		}
	}

	var taddr string
	if common.IsValidIP(root_host) {
		taddr = root_host
		loggo.Info("need_proxy valid ip: %s %s", addr, taddr)
	} else {
		// 同时查询
		cache_addr, find := gDnsCache.Get(host)
		root_cache_addr, root_find := gDnsCache.Get(root_host)
		if find || root_find {
			if find {
				loggo.Info("need_proxy cache hit: %s %v", host, cache_addr)
				taddr = cache_addr
			} else {
				loggo.Info("need_proxy cache root hit: %s %v", root_host, root_cache_addr)
				taddr = root_cache_addr
			}
		} else {
			// 优先使用 gResolver 解析真实 IP
			if gResolver != nil {
				ip, resErr := gResolver.ResolveOne(context.Background(), root_host)
				if resErr == nil && ip != nil {
					taddr = ip.String()
					gDnsCache.Set(root_host, taddr)
					loggo.Info("need_proxy cache root set via gResolver: %s %s", root_host, taddr)
				}
			}
			if taddr == "" {
				taddr, err = common.ResolveDomainToIP(root_host)
				if err == nil {
					gDnsCache.Set(root_host, taddr)
					loggo.Info("need_proxy cache root set: %s %s size %v", root_host, taddr, gDnsCache.Size())
				} else {
					loggo.Error("need_proxy ResolveDomainToIP root error: %s %s", root_host, err)
					taddr, err = common.ResolveDomainToIP(host)
					if err != nil {
						loggo.Error("need_proxy ResolveDomainToIP error: %s %s", host, err)
						return false
					}
					gDnsCache.Set(host, taddr)
					loggo.Info("need_proxy cache set: %s %s size %v", host, taddr, gDnsCache.Size())
				}
			}
		}

		loggo.Info("need_proxy ResolveDomainToIP: %s %s", addr, taddr)
	}

	if common.IsPrivateIP(taddr) {
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

	need_skip := ret != *skip

	return need_skip
}

func getCandidateServers(targetAddr string, srcIP string, srcAddr string) []string {
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

func process(ctx context.Context, conn *net.TCPConn) {
	defer common.CrashLog()
	defer conn.Close()

	var err error = nil
	if err = network.Sock5HandshakeBy(conn, *username, *password); err != nil {
		loggo.Error("process socks handshake: %s", err)
		return
	}
	cmd, _, targetAddr, err := network.Sock5GetRequest(conn)
	if err != nil {
		loggo.Error("process error getting request: %s", err)
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
			process_proxy(conn, targetAddr)
		} else {
			process_direct(conn, targetAddr)
		}
	} else if cmd == network.Socks5CmdUDPAssociate {
		process_udp(ctx, conn, targetAddr)
	} else {
		loggo.Error("process unsupported socks command: %d", cmd)
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
	clientExpectedIP    net.IP
	clientRelayConn     *net.UDPConn

	activeClientUDPAddr atomic.Pointer[net.UDPAddr]
	closed              atomic.Bool
	packetWg            sync.WaitGroup

	directMu   sync.Mutex
	directConn *net.UDPConn

	upstreamMu       sync.Mutex
	upstreamSessions map[string]*udpUpstreamSession
}

func (assoc *udpAssociation) close() {
	if assoc.closed.CompareAndSwap(false, true) {
		if assoc.clientRelayConn != nil {
			_ = assoc.clientRelayConn.Close()
		}
		assoc.directMu.Lock()
		if assoc.directConn != nil {
			_ = assoc.directConn.Close()
		}
		assoc.directMu.Unlock()

		assoc.upstreamMu.Lock()
		for _, s := range assoc.upstreamSessions {
			s.close()
		}
		assoc.upstreamSessions = make(map[string]*udpUpstreamSession)
		assoc.upstreamMu.Unlock()

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
		assoc.handleProxyPacket(targetAddr, pkt)
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
		if cacheIP, ok := gDnsCache.Get(host); ok && cacheIP != "" {
			resolvedHost = cacheIP
		} else {
			rootHost, err := common.GetRootDomain(targetAddr)
			if err == nil {
				if rootCacheIP, ok := gDnsCache.Get(rootHost); ok && rootCacheIP != "" {
					resolvedHost = rootCacheIP
				}
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

func (assoc *udpAssociation) handleProxyPacket(targetAddr string, pkt []byte) {
	candidates := getCandidateServers(targetAddr, assoc.clientTCPRemoteAddr.IP.String(), assoc.clientTCPRemoteAddr.String())
	if len(candidates) == 0 {
		loggo.Error("udp handleProxyPacket no servers fail: %s", targetAddr)
		return
	}

	for _, server := range candidates {
		session, err := assoc.getOrCreateUpstreamSession(server)
		if err != nil {
			loggo.Info("udp getOrCreateUpstreamSession fail: %s %s", server, err)
			continue
		}
		_, err = session.proxyUDPConn.WriteToUDP(pkt, session.upstreamRelay)
		if err != nil {
			loggo.Info("udp WriteToUDP to upstream %s fail: %s", server, err)
			assoc.removeUpstreamSession(server)
			continue
		}
		return
	}
	loggo.Info("udp handleProxyPacket no valid servers: %s", targetAddr)
}

func (assoc *udpAssociation) getOrCreateUpstreamSession(server string) (*udpUpstreamSession, error) {
	assoc.upstreamMu.Lock()
	defer assoc.upstreamMu.Unlock()

	if assoc.closed.Load() {
		return nil, errors.New("association closed")
	}

	if sess, ok := assoc.upstreamSessions[server]; ok {
		return sess, nil
	}

	tcpaddrProxy, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		return nil, err
	}

	proxyTCPConn, err := net.DialTCP("tcp", nil, tcpaddrProxy)
	if err != nil {
		return nil, err
	}

	err = network.Sock5Handshake(proxyTCPConn, 5000, "", "")
	if err != nil {
		_ = proxyTCPConn.Close()
		return nil, err
	}

	bnd, err := network.Sock5SetUDPRequest(proxyTCPConn, "0.0.0.0", 0, 5000)
	if err != nil {
		_ = proxyTCPConn.Close()
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
	loggo.Info("udp established upstream session to %s (relay %s) for client %s", server, relayUDPAddr, assoc.clientTCPRemoteAddr)
	return session, nil
}

func (assoc *udpAssociation) removeUpstreamSession(server string) {
	assoc.upstreamMu.Lock()
	defer assoc.upstreamMu.Unlock()
	if sess, ok := assoc.upstreamSessions[server]; ok {
		sess.close()
		delete(assoc.upstreamSessions, server)
	}
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

	assoc := &udpAssociation{
		clientTCPConn:       conn,
		clientTCPRemoteAddr: remoteTCPAddr,
		clientExpectedIP:    remoteTCPAddr.IP,
		clientRelayConn:     clientRelayConn,
		upstreamSessions:    make(map[string]*udpUpstreamSession),
	}

	if targetHost, targetPortStr, err := net.SplitHostPort(targetAddr); err == nil {
		if targetPort, err := strconv.Atoi(targetPortStr); err == nil && targetPort > 0 {
			targetIP := net.ParseIP(targetHost)
			if targetIP != nil && !targetIP.IsUnspecified() {
				assoc.activeClientUDPAddr.Store(&net.UDPAddr{IP: targetIP, Port: targetPort})
			}
		}
	}

	defer assoc.close()

	go assoc.runClientRelay()

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
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

func process_proxy_server(conn *net.TCPConn, targetAddr string, server string) bool {
	tcpaddrProxy, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		loggo.Info("process_proxy_server tcp ResolveTCPAddr fail: %s %s", server, err.Error())
		return false
	}

	proxyconn, err := net.DialTCP("tcp", nil, tcpaddrProxy)
	if err != nil {
		loggo.Info("process_proxy_server tcp DialTCP fail: %s %s", targetAddr, err.Error())
		return false
	}
	defer proxyconn.Close()

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	err = network.Sock5Handshake(proxyconn, 0, "", "")
	if err != nil {
		loggo.Info("process_proxy_server Sock5Handshake fail: %s %s", targetAddr, err.Error())
		return false
	}

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
		return false
	}

	loggo.Info("client accept new proxy local tcp %s %s %s", server, tcpsrcaddr.String(), targetAddr)

	relay(conn, proxyconn)

	return true
}

func process_proxy(conn *net.TCPConn, targetAddr string) {
	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)
	candidates := getCandidateServers(targetAddr, tcpsrcaddr.IP.String(), tcpsrcaddr.String())
	if len(candidates) == 0 {
		loggo.Error("process_proxy no servers fail: %s", targetAddr)
		return
	}
	for _, server := range candidates {
		if process_proxy_server(conn, targetAddr, server) {
			return
		}
	}
	loggo.Info("process_proxy no valid servers fail: %s", *servers)
}

func process_direct(conn *net.TCPConn, targetAddr string) {
	tcpaddrTarget, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		loggo.Info("process_direct tcp ResolveTCPAddr fail: %s %s", targetAddr, err.Error())
		return
	}

	targetconn, err := net.DialTCP("tcp", nil, tcpaddrTarget)
	if err != nil {
		loggo.Info("process_direct tcp DialTCP fail: %s %s", targetAddr, err.Error())
		return
	}
	defer targetconn.Close()

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	loggo.Info("process_direct client accept new direct local tcp %s %s", tcpsrcaddr.String(), targetAddr)

	relay(conn, targetconn)
}

func relay(c1, c2 *net.TCPConn) {
	var closeOnce sync.Once
	closeBoth := func() {
		_ = c1.Close()
		_ = c2.Close()
	}

	errCh := make(chan error, 2)
	go proxy(c1, c2, c1.RemoteAddr().String(), c2.RemoteAddr().String(), errCh)
	go proxy(c2, c1, c2.RemoteAddr().String(), c1.RemoteAddr().String(), errCh)

	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil && err != io.EOF {
			closeOnce.Do(closeBoth)
		}
	}
	closeOnce.Do(closeBoth)
}

func proxy(destination *net.TCPConn, source *net.TCPConn, dst string, src string, errCh chan error) {
	loggo.Debug("transfer client begin transfer from %s -> %s", src, dst)
	n, err := io.Copy(destination, source)
	_ = destination.CloseWrite()
	errCh <- err
	loggo.Debug("transfer client end transfer from %s -> %s %v %v", src, dst, n, err)
}
