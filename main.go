package main

import (
	"bufio"
	"context"
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
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/lru"
	"github.com/esrrhs/gohome/network"
	"github.com/esrrhs/gohome/thirdparty"
)

var (
	version = "0.4.0"

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

		go process(conn)
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
			// 优先root_host解析
			taddr, err = common.ResolveDomainToIP(root_host)
			if err == nil {
				gDnsCache.Set(root_host, taddr)
				loggo.Info("need_proxy cache root set: %s %s size %v", root_host, taddr, gDnsCache.Size())
			} else {
				loggo.Error("need_proxy ResolveDomainToIP root error: %s %s", root_host, err)
				// 有可能是根域名没有解析，这时候使用原始host继续
				taddr, err = common.ResolveDomainToIP(host)
				if err != nil {
					loggo.Error("need_proxy ResolveDomainToIP error: %s %s", host, err)
					return false
				}
				gDnsCache.Set(host, taddr)
				loggo.Info("need_proxy cache set: %s %s size %v", host, taddr, gDnsCache.Size())
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

func process(conn *net.TCPConn) {
	defer common.CrashLog()
	defer conn.Close()

	var err error = nil
	if err = network.Sock5HandshakeBy(conn, *username, *password); err != nil {
		loggo.Error("process socks handshake: %s", err)
		return
	}
	_, targetAddr, err := network.Sock5GetRequest(conn)
	if err != nil {
		loggo.Error("process error getting request: %s", err)
		return
	}
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
	ss := strings.Fields(*servers)
	if len(ss) <= 0 {
		loggo.Error("process_proxy no servers fail: %s", targetAddr)
		return
	}
	if *sel == "robin" {
		offset := int(gRobinIndex.Add(1) - 1)
		for i := 0; i < len(ss); i++ {
			server := ss[(offset+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, server) {
				return
			}
		}
	} else if *sel == "rand" {
		indexes := rand.Perm(len(ss))
		for _, idx := range indexes {
			server := ss[idx]
			if process_proxy_server(conn, targetAddr, server) {
				return
			}
		}
	} else if *sel == "hash_by_dst_ip" {
		dsthost, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			loggo.Info("process_proxy SplitHostPort error: %s", err)
			return
		}
		hash := int(common.HashString(dsthost) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, server) {
				return
			}
		}
	} else if *sel == "hash_by_src_ip" {
		hash := int(common.HashString(conn.RemoteAddr().(*net.TCPAddr).IP.String()) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, server) {
				return
			}
		}
	} else if *sel == "hash_all" {
		hash := int(common.HashString(conn.RemoteAddr().String()+"-"+targetAddr) % uint64(len(ss)))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, server) {
				return
			}
		}
	} else {
		loggo.Error("process_proxy select type error: %s", *sel)
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
