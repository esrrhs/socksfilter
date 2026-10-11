package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/network"
)

func Test0001(t *testing.T) {
	host, _, err := net.SplitHostPort("123.34.22.41:234")
	if err != nil {
		t.Fatalf("SplitHostPort error: %v", err)
	}
	if !common.IsValidIP(host) {
		t.Errorf("expected 123.34.22.41 to be valid IP")
	}

	host, _, err = net.SplitHostPort("pss.bdstatic.com:443")
	if err != nil {
		t.Fatalf("SplitHostPort error: %v", err)
	}
	if common.IsValidIP(host) {
		t.Errorf("expected pss.bdstatic.com to not be IP")
	}
}

func Test002(t *testing.T) {
	begin := time.Now()
	taddr, err := common.ResolveDomainToIP("www.baidu.com")
	if err != nil {
		t.Logf("ResolveDomainToIP error: %v", err)
		return
	}
	t.Logf("ResolveDomainToIP baidu: %s %v", taddr, time.Since(begin))

	begin = time.Now()
	taddr, err = common.ResolveDomainToIP("www.qq.com")
	if err != nil {
		t.Logf("ResolveDomainToIP error: %v", err)
		return
	}
	t.Logf("ResolveDomainToIP qq: %s %v", taddr, time.Since(begin))
}

func Test003(t *testing.T) {
	init_env()

	if need_proxy("www.baidu.com:443") {
		t.Errorf("expected www.baidu.com to not need proxy")
	}

	// google should need proxy in CN
	if !need_proxy("www.google.com:443") {
		t.Errorf("expected www.google.com to need proxy")
	}
}

func TestPrivateIPDirect(t *testing.T) {
	init_env()

	privateAddrs := []string{
		"127.0.0.1:80",
		"10.0.0.1:8080",
		"192.168.1.1:443",
		"172.16.0.1:22",
	}

	for _, addr := range privateAddrs {
		if need_proxy(addr) {
			t.Errorf("expected private addr %s to not need proxy", addr)
		}
	}
}

func TestIsDirectIP(t *testing.T) {
	direct := []string{
		"127.0.0.1",
		"127.255.255.254",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.1.1",
		"100.64.0.1",
		"0.0.0.0",
		"::1",
		"fe80::1",
		"fc00::1",
		"::",
	}
	for _, ip := range direct {
		if !isDirectIP(ip) {
			t.Errorf("expected %s to be direct", ip)
		}
	}

	notDirect := []string{
		"8.8.8.8",
		"1.1.1.1",
		"172.32.0.1", // 172.16/12 之外
		"100.63.255.255",
		"100.128.0.1", // 100.64/10 之外
		"223.5.5.5",
		"2606:4700:4700::1111",
	}
	for _, ip := range notDirect {
		if isDirectIP(ip) {
			t.Errorf("expected %s to not be direct", ip)
		}
	}

	if isDirectIP("not-an-ip") {
		t.Errorf("expected invalid ip string to not be direct")
	}
}

func TestSkipCountryFlag(t *testing.T) {
	init_env()

	oldSkip := *skip
	defer func() { *skip = oldSkip }()
	*skip = "US"

	// 8.8.8.8 属于 US，skip=US 时应当直连
	if need_proxy("8.8.8.8:53") {
		t.Errorf("expected 8.8.8.8 to not need proxy when skip=US")
	}

	// 223.5.5.5 属于 CN，skip=US 时应当走代理
	if !need_proxy("223.5.5.5:53") {
		t.Errorf("expected 223.5.5.5 to need proxy when skip=US")
	}
}

func TestHashSelectionNoNegative(t *testing.T) {
	ss := strings.Fields("server1:1080 server2:1080 server3:1080")
	if len(ss) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(ss))
	}

	testCases := []string{
		"1.2.3.4",
		"255.255.255.255",
		"example.com",
		"very.long.domain.name.with.many.subdomains.example.org",
		"192.168.1.100-10.0.0.1:8080",
	}

	for _, tc := range testCases {
		hashVal := common.HashString(tc)
		idx := int(hashVal % uint64(len(ss)))
		if idx < 0 || idx >= len(ss) {
			t.Fatalf("index %d out of bounds [0, %d)", idx, len(ss))
		}
		for i := 0; i < len(ss); i++ {
			selIdx := (idx + i) % len(ss)
			if selIdx < 0 || selIdx >= len(ss) {
				t.Fatalf("selection index %d out of bounds", selIdx)
			}
		}
	}
}

func TestRobinRotation(t *testing.T) {
	ss := strings.Fields("s1 s2 s3")
	gRobinIndex.Store(0)

	first := int((gRobinIndex.Add(1) - 1) % uint64(len(ss)))
	second := int((gRobinIndex.Add(1) - 1) % uint64(len(ss)))
	third := int((gRobinIndex.Add(1) - 1) % uint64(len(ss)))
	fourth := int((gRobinIndex.Add(1) - 1) % uint64(len(ss)))

	if first != 0 || second != 1 || third != 2 || fourth != 0 {
		t.Errorf("round robin rotation unexpected: %d %d %d %d", first, second, third, fourth)
	}
}

func TestGetCandidateServers(t *testing.T) {
	oldServers := *servers
	oldSel := *sel
	defer func() {
		*servers = oldServers
		*sel = oldSel
	}()

	*servers = "server1:1080 server2:1080 server3:1080"
	*sel = "robin"
	gRobinIndex.Store(0)

	c1 := getCandidateServers("example.com:80", "127.0.0.1", "127.0.0.1:1234")
	if len(c1) != 3 || c1[0] != "server1:1080" {
		t.Errorf("robin 1 unexpected: %v", c1)
	}
	c2 := getCandidateServers("example.com:80", "127.0.0.1", "127.0.0.1:1234")
	if len(c2) != 3 || c2[0] != "server2:1080" {
		t.Errorf("robin 2 unexpected: %v", c2)
	}

	*sel = "rand"
	cRand := getCandidateServers("example.com:80", "127.0.0.1", "127.0.0.1:1234")
	if len(cRand) != 3 {
		t.Errorf("rand length unexpected: %v", cRand)
	}

	*sel = "hash_by_dst_ip"
	cDst := getCandidateServers("8.8.8.8:53", "127.0.0.1", "127.0.0.1:1234")
	if len(cDst) != 3 {
		t.Errorf("hash_by_dst_ip unexpected: %v", cDst)
	}

	*sel = "hash_by_src_ip"
	cSrc := getCandidateServers("8.8.8.8:53", "127.0.0.1", "127.0.0.1:1234")
	if len(cSrc) != 3 {
		t.Errorf("hash_by_src_ip unexpected: %v", cSrc)
	}

	*sel = "hash_all"
	cAll := getCandidateServers("8.8.8.8:53", "127.0.0.1", "127.0.0.1:1234")
	if len(cAll) != 3 {
		t.Errorf("hash_all unexpected: %v", cAll)
	}
}

func TestUDPAssociateDirect(t *testing.T) {
	init_env()

	// 1. Setup local echo UDP server
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("echo UDP listen fail: %v", err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	var echoWg sync.WaitGroup
	echoWg.Add(1)
	go func() {
		defer echoWg.Done()
		buf := make([]byte, 1024)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], src)
		}
	}()

	// 2. Setup socksfilter listener
	sfListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var sfWg sync.WaitGroup
	sfWg.Add(1)
	go func() {
		defer sfWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := sfListener.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	// 3. Connect client to socksfilter
	clientTCP, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("client dial sf fail: %v", err)
	}

	if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}

	bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
	if err != nil {
		t.Fatalf("SetUDPRequest fail: %v", err)
	}

	relayUDPAddr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		t.Fatalf("ResolveUDPAddr fail: %v", err)
	}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client UDP listen fail: %v", err)
	}
	defer clientUDP.Close()

	// 4. Send packet to echo server (127.0.0.1 is direct)
	payload := []byte("hello-socksfilter-udp-direct")
	pkt, err := network.Sock5PackUDP(echoAddr.IP.String(), echoAddr.Port, payload)
	if err != nil {
		t.Fatalf("PackUDP fail: %v", err)
	}

	if _, err := clientUDP.WriteToUDP(pkt, relayUDPAddr); err != nil {
		t.Fatalf("WriteToUDP fail: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1024)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP timeout/error: %v", err)
	}

	host, port, data, err := network.Sock5UnpackUDP(respBuf[:n])
	if err != nil {
		t.Fatalf("UnpackUDP fail: %v", err)
	}
	if host != echoAddr.IP.String() || port != echoAddr.Port {
		t.Errorf("expected echo from %s:%d, got %s:%d", echoAddr.IP, echoAddr.Port, host, port)
	}
	if string(data) != string(payload) {
		t.Errorf("expected payload %q, got %q", payload, data)
	}

	_ = clientTCP.Close()
	cancel()
	_ = sfListener.Close()
	sfWg.Wait()
	_ = echoConn.Close()
	echoWg.Wait()
}

func TestUDPAssociateProxy(t *testing.T) {
	init_env()

	// 1. Setup mock upstream SOCKS5 server that supports UDP ASSOCIATE
	mockUpstreamTCP, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("mock upstream TCP listen fail: %v", err)
	}

	mockUpstreamUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("mock upstream UDP listen fail: %v", err)
	}

	var upstreamWg sync.WaitGroup
	upstreamWg.Add(1)
	go func() {
		defer upstreamWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := mockUpstreamTCP.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				defer c.Close()
				if err := network.Sock5HandshakeBy(c, "", ""); err != nil {
					return
				}
				cmd, _, _, err := network.Sock5GetRequest(c)
				if err != nil || cmd != network.Socks5CmdUDPAssociate {
					return
				}
				_ = network.Sock5SendConnectReply(c, 0x00, mockUpstreamUDP.LocalAddr().String())
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Upstream UDP relay echo logic
	upstreamWg.Add(1)
	go func() {
		defer upstreamWg.Done()
		buf := make([]byte, 65535)
		for {
			n, src, err := mockUpstreamUDP.ReadFromUDP(buf)
			if err != nil {
				return
			}
			host, port, data, err := network.Sock5UnpackUDP(buf[:n])
			if err != nil {
				continue
			}
			respData := append([]byte("proxied:"), data...)
			respPkt, err := network.Sock5PackUDP(host, port, respData)
			if err != nil {
				continue
			}
			_, _ = mockUpstreamUDP.WriteToUDP(respPkt, src)
		}
	}()

	// 2. Setup socksfilter pointing to mock upstream
	oldServers := *servers
	*servers = mockUpstreamTCP.Addr().String()

	sfListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var sfWg sync.WaitGroup
	sfWg.Add(1)
	go func() {
		defer sfWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := sfListener.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	// 3. Connect client to socksfilter
	clientTCP, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("client dial sf fail: %v", err)
	}

	if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}

	bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
	if err != nil {
		t.Fatalf("SetUDPRequest fail: %v", err)
	}

	relayUDPAddr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		t.Fatalf("ResolveUDPAddr fail: %v", err)
	}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client UDP listen fail: %v", err)
	}
	defer clientUDP.Close()

	// 4. Send packet to a target that requires proxy (8.8.8.8:53)
	payload := []byte("dns-query-data")
	pkt, err := network.Sock5PackUDP("8.8.8.8", 53, payload)
	if err != nil {
		t.Fatalf("PackUDP fail: %v", err)
	}

	if _, err := clientUDP.WriteToUDP(pkt, relayUDPAddr); err != nil {
		t.Fatalf("WriteToUDP fail: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1024)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP timeout/error: %v", err)
	}

	host, port, data, err := network.Sock5UnpackUDP(respBuf[:n])
	if err != nil {
		t.Fatalf("UnpackUDP fail: %v", err)
	}
	if host != "8.8.8.8" || port != 53 {
		t.Errorf("expected host 8.8.8.8:53, got %s:%d", host, port)
	}
	if string(data) != "proxied:dns-query-data" {
		t.Errorf("expected 'proxied:dns-query-data', got %q", string(data))
	}

	_ = clientTCP.Close()
	cancel()
	_ = sfListener.Close()
	sfWg.Wait()
	_ = mockUpstreamTCP.Close()
	_ = mockUpstreamUDP.Close()
	upstreamWg.Wait()

	*servers = oldServers
}

// startMockUDPRelay 启动一个支持 UDP ASSOCIATE 的 mock 上游 SOCKS5，
// 返回其 TCP 地址和收到的 UDP 包计数器，响应加 prefix 前缀以区分上游。
// user 非空时要求客户端使用该用户名/密码认证。
func startMockUDPRelay(t *testing.T, prefix, user, pass string) (string, *atomic.Int64, func()) {
	t.Helper()

	mockTCP, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("mock upstream TCP listen fail: %v", err)
	}
	mockUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("mock upstream UDP listen fail: %v", err)
	}

	var count atomic.Int64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := mockTCP.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				defer c.Close()
				if err := network.Sock5HandshakeBy(c, user, pass); err != nil {
					return
				}
				cmd, _, _, err := network.Sock5GetRequest(c)
				if err != nil || cmd != network.Socks5CmdUDPAssociate {
					return
				}
				_ = network.Sock5SendConnectReply(c, 0x00, mockUDP.LocalAddr().String())
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, src, err := mockUDP.ReadFromUDP(buf)
			if err != nil {
				return
			}
			host, port, data, err := network.Sock5UnpackUDP(buf[:n])
			if err != nil {
				continue
			}
			count.Add(1)
			respPkt, err := network.Sock5PackUDP(host, port, append([]byte(prefix), data...))
			if err != nil {
				continue
			}
			_, _ = mockUDP.WriteToUDP(respPkt, src)
		}
	}()

	cleanup := func() {
		_ = mockTCP.Close()
		_ = mockUDP.Close()
		wg.Wait()
	}
	return mockTCP.Addr().String(), &count, cleanup
}

func TestUDPAssociateStickyUpstream(t *testing.T) {
	init_env()

	srv1, count1, cleanup1 := startMockUDPRelay(t, "s1:", "", "")
	defer cleanup1()
	srv2, count2, cleanup2 := startMockUDPRelay(t, "s2:", "", "")
	defer cleanup2()

	oldServers := *servers
	oldSel := *sel
	defer func() {
		*servers = oldServers
		*sel = oldSel
	}()
	*servers = srv1 + " " + srv2
	*sel = "robin"

	sfListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var sfWg sync.WaitGroup
	sfWg.Add(1)
	go func() {
		defer sfWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := sfListener.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	clientTCP, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("client dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}
	bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
	if err != nil {
		t.Fatalf("SetUDPRequest fail: %v", err)
	}
	relayUDPAddr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		t.Fatalf("ResolveUDPAddr fail: %v", err)
	}
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client UDP listen fail: %v", err)
	}
	defer clientUDP.Close()

	// 向同一目标连发 3 个包
	payloads := []string{"p0", "p1", "p2"}
	for _, p := range payloads {
		pkt, err := network.Sock5PackUDP("8.8.8.8", 53, []byte(p))
		if err != nil {
			t.Fatalf("PackUDP fail: %v", err)
		}
		if _, err := clientUDP.WriteToUDP(pkt, relayUDPAddr); err != nil {
			t.Fatalf("WriteToUDP fail: %v", err)
		}
	}

	prefixes := make(map[string]int)
	for i := 0; i < len(payloads); i++ {
		_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 1024)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("ReadFromUDP %d timeout/error: %v", i, err)
		}
		_, _, data, err := network.Sock5UnpackUDP(respBuf[:n])
		if err != nil {
			t.Fatalf("UnpackUDP fail: %v", err)
		}
		switch {
		case strings.HasPrefix(string(data), "s1:"):
			prefixes["s1"]++
		case strings.HasPrefix(string(data), "s2:"):
			prefixes["s2"]++
		default:
			t.Fatalf("unexpected response prefix: %q", string(data))
		}
	}

	// 同一目标的所有包必须全部落到同一个上游
	if prefixes["s1"] != 3 && prefixes["s2"] != 3 {
		t.Errorf("expected all 3 packets pinned to one upstream, got s1=%d s2=%d", prefixes["s1"], prefixes["s2"])
	}
	if count1.Load() != 3 && count2.Load() != 3 {
		t.Errorf("expected one upstream to receive 3 packets, got s1=%d s2=%d", count1.Load(), count2.Load())
	}
	if count1.Load()+count2.Load() != 3 {
		t.Errorf("expected exactly 3 upstream packets total, got s1=%d s2=%d", count1.Load(), count2.Load())
	}

	_ = clientTCP.Close()
	cancel()
	_ = sfListener.Close()
	sfWg.Wait()
}

func TestUDPAssociateFailover(t *testing.T) {
	init_env()

	// 一个正常工作的上游；另一个用必然拒连的端口模拟故障
	goodAddr, count, cleanupGood := startMockUDPRelay(t, "good:", "", "")
	defer cleanupGood()
	deadAddr := "127.0.0.1:1"

	oldServers := *servers
	oldSel := *sel
	defer func() {
		*servers = oldServers
		*sel = oldSel
	}()
	*sel = "hash_by_dst_ip"

	// 确保 hash 排序后故障节点排在首位，首个包必然先尝试故障节点
	dstHost := "8.8.8.8"
	if int(common.HashString(dstHost)%2) == 0 {
		*servers = deadAddr + " " + goodAddr
	} else {
		*servers = goodAddr + " " + deadAddr
	}

	sfListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var sfWg sync.WaitGroup
	sfWg.Add(1)
	go func() {
		defer sfWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := sfListener.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	clientTCP, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("client dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}
	bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
	if err != nil {
		t.Fatalf("SetUDPRequest fail: %v", err)
	}
	relayUDPAddr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		t.Fatalf("ResolveUDPAddr fail: %v", err)
	}
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client UDP listen fail: %v", err)
	}
	defer clientUDP.Close()

	// 连发 2 个包：首个触发 failover 并重绑定，第二个应直接走已绑定的可用上游
	for i := 0; i < 2; i++ {
		pkt, err := network.Sock5PackUDP(dstHost, 53, []byte("x"))
		if err != nil {
			t.Fatalf("PackUDP fail: %v", err)
		}
		if _, err := clientUDP.WriteToUDP(pkt, relayUDPAddr); err != nil {
			t.Fatalf("WriteToUDP fail: %v", err)
		}
		_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 1024)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("packet %d ReadFromUDP timeout/error: %v", i, err)
		}
		_, _, data, err := network.Sock5UnpackUDP(respBuf[:n])
		if err != nil || string(data) != "good:x" {
			t.Fatalf("packet %d expected failover response 'good:x', got %q err=%v", i, string(data), err)
		}
	}

	if count.Load() != 2 {
		t.Errorf("expected working upstream to receive 2 packets, got %d", count.Load())
	}

	_ = clientTCP.Close()
	cancel()
	_ = sfListener.Close()
	sfWg.Wait()
}

// startSocksfilterListener 启动一个进程内 socksfilter 监听器，返回地址与清理函数。
func startSocksfilterListener(t *testing.T) (string, func()) {
	t.Helper()

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	cleanup := func() {
		cancel()
		_ = l.Close()
		wg.Wait()
	}
	return l.Addr().String(), cleanup
}

// startAuthConnectUpstream 启动要求账密认证的 mock 上游，CONNECT 成功后
// 固定转发到 echoAddr（忽略客户端请求的目标），用于验证上游认证链路。
func startAuthConnectUpstream(t *testing.T, user, pass, echoAddr string) (string, func()) {
	t.Helper()

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("upstream listen fail: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				defer c.Close()
				if err := network.Sock5HandshakeBy(c, user, pass); err != nil {
					return
				}
				if cmd, _, _, err := network.Sock5GetRequest(c); err != nil || cmd != network.Socks5CmdConnect {
					return
				}
				_ = network.Sock5SendConnectReply(c, 0x00, echoAddr)
				up, err := net.Dial("tcp", echoAddr)
				if err != nil {
					return
				}
				defer up.Close()
				var relayWg sync.WaitGroup
				relayWg.Add(2)
				go func() {
					defer relayWg.Done()
					_, _ = io.Copy(up, c)
					_ = up.(*net.TCPConn).CloseWrite()
				}()
				go func() {
					defer relayWg.Done()
					_, _ = io.Copy(c, up)
					_ = c.CloseWrite()
				}()
				relayWg.Wait()
			}(conn)
		}
	}()

	cleanup := func() {
		_ = l.Close()
		wg.Wait()
	}
	return l.Addr().String(), cleanup
}

// withGlobalFlags 保存并恢复全局 flag。调用方必须保证写入期间没有连接 goroutine
// 在读这些 flag（先建监听器前设置、关闭监听器后恢复）。
func withGlobalFlags(t *testing.T, srv, sUser, sPass string) {
	t.Helper()
	oldServers, oldSUser, oldSPass := *servers, *susername, *spassword
	t.Cleanup(func() {
		*servers, *susername, *spassword = oldServers, oldSUser, oldSPass
	})
	*servers, *susername, *spassword = srv, sUser, sPass
}

func TestUpstreamAuthTCPConnect(t *testing.T) {
	init_env()

	// 本地 echo TCP 服务器
	echoLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("echo listen fail: %v", err)
	}
	var echoWg sync.WaitGroup
	echoWg.Add(1)
	go func() {
		defer echoWg.Done()
		for {
			c, err := echoLn.AcceptTCP()
			if err != nil {
				return
			}
			go func(conn *net.TCPConn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = echoLn.Close()
		echoWg.Wait()
	})

	// 要求认证的 mock 上游
	upstreamAddr, cleanupUp := startAuthConnectUpstream(t, "upuser", "uppass", echoLn.Addr().String())
	t.Cleanup(cleanupUp)

	// 每个场景独立配置 flag 与监听器，teardown 等待全部连接 goroutine 退出，
	// 避免与 flag 读取发生数据竞争。
	tryConnect := func(sUser, sPass string, wantEcho bool) {
		withGlobalFlags(t, upstreamAddr, sUser, sPass)
		sfAddr, cleanupSF := startSocksfilterListener(t)

		client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
		if err != nil {
			cleanupSF()
			t.Fatalf("dial sf fail: %v", err)
		}
		if err := network.Sock5Handshake(client, 2000, "", ""); err != nil {
			cleanupSF()
			t.Fatalf("client handshake fail: %v", err)
		}
		// 8.8.8.8 必然判定为需要代理，mock 上游会忽略目标并转发到 echo
		if err := network.Sock5SetRequest(client, "8.8.8.8", 53, 2000); err != nil {
			cleanupSF()
			t.Fatalf("client SetRequest fail: %v", err)
		}

		if _, err := client.Write([]byte("auth-ping")); err != nil {
			cleanupSF()
			t.Fatalf("write fail: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 32)
		n, err := client.Read(buf)
		_ = client.Close()
		cleanupSF()

		if wantEcho {
			if err != nil || string(buf[:n]) != "auth-ping" {
				t.Fatalf("expected echo with correct upstream creds, got n=%d err=%v data=%q", n, err, string(buf[:n]))
			}
		} else {
			if err == nil {
				t.Errorf("expected upstream auth failure to break the tunnel, got echo %q", string(buf[:n]))
			}
		}
	}

	tryConnect("upuser", "uppass", true)
	tryConnect("upuser", "badpass", false)
}

func TestUpstreamAuthUDPAssociate(t *testing.T) {
	init_env()

	upstreamAddr, _, cleanupUp := startMockUDPRelay(t, "authed:", "upuser", "uppass")
	t.Cleanup(cleanupUp)

	tryAssociate := func(sUser, sPass string, wantResponse bool) {
		withGlobalFlags(t, upstreamAddr, sUser, sPass)
		sfAddr, cleanupSF := startSocksfilterListener(t)

		clientTCP, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
		if err != nil {
			cleanupSF()
			t.Fatalf("dial sf fail: %v", err)
		}
		if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
			cleanupSF()
			t.Fatalf("handshake fail: %v", err)
		}
		bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
		if err != nil {
			cleanupSF()
			t.Fatalf("SetUDPRequest fail: %v", err)
		}
		relay, err := net.ResolveUDPAddr("udp", bnd)
		if err != nil {
			cleanupSF()
			t.Fatalf("ResolveUDPAddr fail: %v", err)
		}
		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			cleanupSF()
			t.Fatalf("client UDP listen fail: %v", err)
		}

		pkt, _ := network.Sock5PackUDP("8.8.8.8", 53, []byte("payload"))
		if _, err := clientUDP.WriteToUDP(pkt, relay); err != nil {
			cleanupSF()
			t.Fatalf("WriteToUDP fail: %v", err)
		}
		_ = clientUDP.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		resp := make([]byte, 1024)
		n, _, readErr := clientUDP.ReadFromUDP(resp)

		_ = clientTCP.Close()
		_ = clientUDP.Close()
		cleanupSF()

		if wantResponse {
			if readErr != nil {
				t.Fatalf("expected authed upstream response, got: %v", readErr)
			}
			_, _, data, uerr := network.Sock5UnpackUDP(resp[:n])
			if uerr != nil || string(data) != "authed:payload" {
				t.Fatalf("unexpected response: %q err=%v", string(data), uerr)
			}
		} else {
			if readErr == nil {
				h, p, d, _ := network.Sock5UnpackUDP(resp[:n])
				t.Errorf("expected no response with wrong upstream creds, got %d bytes from %s:%d data=%q", n, h, p, string(d))
			}
		}
	}

	tryAssociate("upuser", "uppass", true)
	tryAssociate("upuser", "badpass", false)
}

func mustTCPAddr(t *testing.T, addr string) *net.TCPAddr {
	t.Helper()
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("ResolveTCPAddr fail: %v", err)
	}
	return tcpAddr
}

func TestUDPAssociateAuth(t *testing.T) {
	oldUser := *username
	oldPass := *password
	*username = "myuser"
	*password = "mypass"

	sfListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf TCP listen fail: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var sfWg sync.WaitGroup
	sfWg.Add(1)
	go func() {
		defer sfWg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			conn, err := sfListener.AcceptTCP()
			if err != nil {
				return
			}
			connWg.Add(1)
			go func(c *net.TCPConn) {
				defer connWg.Done()
				process(ctx, c)
			}(conn)
		}
	}()

	// 1. Wrong credentials should fail handshake
	clientTCP1, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	if err := network.Sock5Handshake(clientTCP1, 2000, "myuser", "wrongpass"); err == nil {
		t.Errorf("expected handshake error with wrong password")
	}
	_ = clientTCP1.Close()

	// 2. Correct credentials should succeed
	clientTCP2, err := net.DialTCP("tcp", nil, sfListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	if err := network.Sock5Handshake(clientTCP2, 2000, "myuser", "mypass"); err != nil {
		t.Fatalf("expected handshake success: %v", err)
	}
	bnd, err := network.Sock5SetUDPRequest(clientTCP2, "0.0.0.0", 0, 2000)
	if err != nil {
		t.Fatalf("expected SetUDPRequest success: %v", err)
	}
	if bnd == "" {
		t.Errorf("expected non-empty bnd address")
	}
	_ = clientTCP2.Close()

	cancel()
	_ = sfListener.Close()
	sfWg.Wait()

	*username = oldUser
	*password = oldPass
}

func BenchmarkLoadChinaDomains(b *testing.B) {
	for i := 0; i < b.N; i++ {
		load_china_domains()
	}
}

// resetUpstreamHealth 清空全局健康状态，仅供测试隔离使用。
func resetUpstreamHealth() {
	gUpstreamHealth.Range(func(k, _ any) bool {
		gUpstreamHealth.Delete(k)
		return true
	})
}

// startGatedSocks5 启动 mock SOCKS5 上游：前 failN 个连接直接断开（模拟故障），
// 之后的连接正常完成 SOCKS5 握手（模拟恢复），地址全程不变。
func startGatedSocks5(t *testing.T, failN int64) (string, func()) {
	t.Helper()

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("gated upstream listen fail: %v", err)
	}

	var accepted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var connWg sync.WaitGroup
		defer connWg.Wait()
		for {
			c, err := l.AcceptTCP()
			if err != nil {
				return
			}
			n := accepted.Add(1)
			connWg.Add(1)
			go func(conn *net.TCPConn, fail bool) {
				defer connWg.Done()
				defer conn.Close()
				if fail {
					return // 直接断开，握手必然失败
				}
				if err := network.Sock5HandshakeBy(conn, "", ""); err != nil {
					return
				}
				buf := make([]byte, 1)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}(c, n <= failN)
		}
	}()

	cleanup := func() {
		_ = l.Close()
		wg.Wait()
	}
	return l.Addr().String(), cleanup
}

func TestHealthCheckDeadThenRecover(t *testing.T) {
	resetUpstreamHealth()

	// 前 2 个连接失败，第 3 个起正常
	addr, cleanup := startGatedSocks5(t, 2)
	defer cleanup()
	t.Cleanup(resetUpstreamHealth)

	timeout := 2 * time.Second

	// 第 1 次失败：未达阈值，仍标记为可用
	if checkUpstream(addr, timeout) {
		t.Fatal("first probe expected to fail")
	}
	if !isServerAlive(addr) {
		t.Error("server should stay alive after 1 failure (threshold is 2)")
	}

	// 第 2 次失败：摘除
	if checkUpstream(addr, timeout) {
		t.Fatal("second probe expected to fail")
	}
	if isServerAlive(addr) {
		t.Error("server should be marked dead after 2 consecutive failures")
	}

	// 第 3 次探测成功：立即恢复
	if !checkUpstream(addr, timeout) {
		t.Fatal("third probe expected to succeed")
	}
	if !isServerAlive(addr) {
		t.Error("server should be alive again after one successful probe")
	}
}

// TestHealthCheckProbeCounters 验证主动健康探测计数：前 2 次失败第 3 次成功的
// gated 上游，probeAttempts=3、probeFails=2（成功次数=差值 1）；被动流量
// 反馈不经过 checkUpstream，不得计入探测桶。
func TestHealthCheckProbeCounters(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	addr, cleanup := startGatedSocks5(t, 2)
	defer cleanup()

	timeout := 2 * time.Second
	if checkUpstream(addr, timeout) {
		t.Fatal("first probe expected to fail")
	}
	if checkUpstream(addr, timeout) {
		t.Fatal("second probe expected to fail")
	}
	if !checkUpstream(addr, timeout) {
		t.Fatal("third probe expected to succeed")
	}

	h := getUpstreamHealth(addr)
	if got := h.probeAttempts.Load(); got != 3 {
		t.Errorf("probeAttempts=%d, want 3", got)
	}
	if got := h.probeFails.Load(); got != 2 {
		t.Errorf("probeFails=%d, want 2", got)
	}
	if got := h.probeAttempts.Load() - h.probeFails.Load(); got != 1 {
		t.Errorf("probe successes=%d, want 1", got)
	}

	// 每次探测（成功/失败均含）都应记录耗时：超时上限 2s，3 次观测必然全部
	// 落在 10s 以内的有限桶中，累计和不小于最近一次耗时。
	if h.probeLastNS.Load() <= 0 {
		t.Error("probeLastNS not recorded")
	}
	if h.probeSumNS.Load() < h.probeLastNS.Load() {
		t.Errorf("probeSumNS=%d < probeLastNS=%d", h.probeSumNS.Load(), h.probeLastNS.Load())
	}
	var inFiniteBuckets int64
	for i := range h.probeLatencyBuckets {
		inFiniteBuckets += h.probeLatencyBuckets[i].Load()
	}
	if inFiniteBuckets != 3 {
		t.Errorf("observations in finite buckets=%d, want 3 (probe timeout 2s < 10s max bound)", inFiniteBuckets)
	}

	// 被动失败反馈只影响健康状态，不计入主动探测桶
	beforeA, beforeF := h.probeAttempts.Load(), h.probeFails.Load()
	beforeLast, beforeSum := h.probeLastNS.Load(), h.probeSumNS.Load()
	reportUpstreamFailure(addr, trafficFailStageHandshake, "synthetic passive failure")
	if h.probeAttempts.Load() != beforeA || h.probeFails.Load() != beforeF {
		t.Error("passive traffic failure must not move active probe counters")
	}
	if h.probeLastNS.Load() != beforeLast || h.probeSumNS.Load() != beforeSum {
		t.Error("passive traffic failure must not move active probe latency")
	}
}

// TestUpstreamHealthTransitions 验证健康状态翻转计数：只有真正的
// alive->dead（连续失败达阈值）与 dead->alive 才计数，半开期重复失败、
// 健康态下的成功/单次失败都不计数；多轮 flapping 累计递增。
func TestUpstreamHealthTransitions(t *testing.T) {
	h := &upstreamHealth{}
	h.alive.Store(true)
	now := time.Now()

	if h.recordSuccess() {
		t.Fatal("recordSuccess on healthy upstream must not report a transition")
	}
	if h.markedDead.Load() != 0 || h.recovered.Load() != 0 {
		t.Fatal("counters must start at zero")
	}

	// 第一次失败未达阈值：不翻转
	if h.recordFailure(now) {
		t.Fatal("first failure must not mark dead")
	}
	// 第二次失败达阈值：alive -> dead
	if !h.recordFailure(now) {
		t.Fatal("second consecutive failure must mark dead")
	}
	if h.markedDead.Load() != 1 {
		t.Errorf("markedDead=%d, want 1", h.markedDead.Load())
	}
	// 摘除后的额外失败（含半开期重试失败）不重复计数
	if h.recordFailure(now) {
		t.Fatal("failure while already dead must not report a transition")
	}
	if h.markedDead.Load() != 1 {
		t.Errorf("markedDead=%d, want still 1", h.markedDead.Load())
	}

	// 一次成功恢复：dead -> alive
	if !h.recordSuccess() {
		t.Fatal("success while dead must report a recovery")
	}
	if h.recovered.Load() != 1 {
		t.Errorf("recovered=%d, want 1", h.recovered.Load())
	}
	// 健康态下的成功不重复计数
	if h.recordSuccess() {
		t.Fatal("success while healthy must not report a transition")
	}
	if h.recovered.Load() != 1 {
		t.Errorf("recovered=%d, want still 1", h.recovered.Load())
	}

	// 第二轮 flapping：计数继续累加
	h.recordFailure(now)
	if !h.recordFailure(now) {
		t.Fatal("expected second alive->dead transition")
	}
	if !h.recordSuccess() {
		t.Fatal("expected second dead->alive transition")
	}
	if h.markedDead.Load() != 2 || h.recovered.Load() != 2 {
		t.Errorf("after second flap markedDead=%d recovered=%d, want 2/2", h.markedDead.Load(), h.recovered.Load())
	}
}

func TestHealthCheckUnreachableDead(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	// 127.0.0.1:1 必然拒连
	dead := "127.0.0.1:1"
	timeout := time.Second
	checkUpstream(dead, timeout)
	if !isServerAlive(dead) {
		t.Error("expected still alive after first failure")
	}
	checkUpstream(dead, timeout)
	if isServerAlive(dead) {
		t.Error("expected unreachable upstream to be marked dead after threshold")
	}
}

func TestFilterAliveServers(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	a, b, c := "127.0.0.1:11", "127.0.0.1:22", "127.0.0.1:33"
	getUpstreamHealth(b).alive.Store(false)

	got := filterAliveServers([]string{a, b, c})
	if len(got) != 2 || got[0] != a || got[1] != c {
		t.Errorf("expected [a c] after filtering b, got %v", got)
	}

	// 全部不可用时 fail-open，保留原列表
	getUpstreamHealth(a).alive.Store(false)
	getUpstreamHealth(c).alive.Store(false)
	allDead := filterAliveServers([]string{a, b, c})
	if len(allDead) != 3 {
		t.Errorf("expected fail-open to return all candidates, got %v", allDead)
	}
}

func TestGetCandidateServersFiltersDead(t *testing.T) {
	resetUpstreamHealth()

	oldServers, oldSel := *servers, *sel
	t.Cleanup(func() {
		*servers, *sel = oldServers, oldSel
		resetUpstreamHealth()
	})

	alive1, alive2, dead := "127.0.0.1:101", "127.0.0.1:102", "127.0.0.1:103"
	*servers = alive1 + " " + dead + " " + alive2
	*sel = "robin"
	getUpstreamHealth(dead).alive.Store(false)

	// 连续取多轮候选，任何一轮都不应包含已摘除节点，且必须保留两个活节点
	for i := 0; i < 6; i++ {
		got := getCandidateServers("8.8.8.8:53", "127.0.0.1", "127.0.0.1:9999")
		if len(got) != 2 {
			t.Fatalf("round %d: expected 2 alive candidates, got %v", i, got)
		}
		for _, s := range got {
			if s == dead {
				t.Fatalf("round %d: dead upstream leaked into candidates: %v", i, got)
			}
		}
	}
}

func TestTargetCandidateOrderRepinsWhenPinnedDead(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	alive1, alive2, pinnedDead := "127.0.0.1:201", "127.0.0.1:202", "127.0.0.1:203"
	getUpstreamHealth(pinnedDead).alive.Store(false)

	assoc := &udpAssociation{
		upstreamSessions: make(map[string]*udpUpstreamSession),
		targetServers:    make(map[string]string),
	}
	target := "8.8.8.8:53"
	// 模拟历史粘性：目标原本绑定在后来故障摘除的节点上
	assoc.targetServers[target] = pinnedDead

	// 候选列表已不含故障节点（模拟 getCandidateServers 的过滤结果）
	candidates := []string{alive1, alive2}
	pinned, ordered := targetCandidateOrder(assoc, target, candidates)

	if pinned != alive1 {
		t.Errorf("expected repin to %s, got %s", alive1, pinned)
	}
	if len(ordered) != 2 || ordered[0] != alive1 || ordered[1] != alive2 {
		t.Errorf("unexpected order: %v", ordered)
	}
	if assoc.targetServers[target] != alive1 {
		t.Errorf("expected pin map updated to %s, got %s", alive1, assoc.targetServers[target])
	}

	// 再次调用：已绑定节点在候选中，顺序以它为首且不发生改绑
	pinned2, ordered2 := targetCandidateOrder(assoc, target, []string{alive2, alive1})
	if pinned2 != alive1 || ordered2[0] != alive1 || ordered2[1] != alive2 {
		t.Errorf("expected sticky alive1 first, got pinned=%s order=%v", pinned2, ordered2)
	}
}

func TestPassiveHealthFailureRecovery(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv := "127.0.0.1:301"
	reportUpstreamFailure(srv, trafficFailStageDial, "first error")
	if !isServerAlive(srv) {
		t.Fatal("server should remain alive after first passive failure")
	}
	reportUpstreamFailure(srv, trafficFailStageHandshake, "second error")
	if isServerAlive(srv) {
		t.Fatal("server should be marked dead after threshold")
	}

	// 一次真实流量成功即恢复并清零计数
	reportUpstreamSuccess(srv)
	if !isServerAlive(srv) {
		t.Fatal("server should recover on traffic success")
	}
	// 计数已清零：恢复后只再失败一次不应立即摘除
	reportUpstreamFailure(srv, trafficFailStageWrite, "one more error")
	if !isServerAlive(srv) {
		t.Fatal("single failure after recovery should not mark dead (counter must reset)")
	}

	// 失败阶段分类计数不受健康翻转影响，累计保留
	h := getUpstreamHealth(srv)
	if h.trafficFailsDial.Load() != 1 || h.trafficFailsHandshake.Load() != 1 || h.trafficFailsWrite.Load() != 1 {
		t.Errorf("traffic fail buckets dial=%d handshake=%d write=%d, want 1/1/1",
			h.trafficFailsDial.Load(), h.trafficFailsHandshake.Load(), h.trafficFailsWrite.Load())
	}
}

// TestReportUpstreamFailureStageBuckets 验证被动失败按阶段分桶：三类各自
// 累计、互不串桶；主动探测路径不得移动这些桶；未知阶段不计入任何桶。
func TestReportUpstreamFailureStageBuckets(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv := "127.0.0.1:302"
	// 每次成功清零健康 fails，保证后续反馈不会因阈值摘除而影响分类计数
	reportUpstreamFailure(srv, trafficFailStageDial, "d1")
	reportUpstreamFailure(srv, trafficFailStageDial, "d2")
	reportUpstreamFailure(srv, trafficFailStageHandshake, "h1")
	reportUpstreamSuccess(srv)
	reportUpstreamFailure(srv, trafficFailStageWrite, "w1")
	reportUpstreamFailure(srv, "unknown-stage", "ignored")

	h := getUpstreamHealth(srv)
	if got := h.trafficFailCount(trafficFailStageDial); got != 2 {
		t.Errorf("dial bucket=%d, want 2", got)
	}
	if got := h.trafficFailCount(trafficFailStageHandshake); got != 1 {
		t.Errorf("handshake bucket=%d, want 1", got)
	}
	if got := h.trafficFailCount(trafficFailStageWrite); got != 1 {
		t.Errorf("write bucket=%d, want 1", got)
	}
	if got := h.trafficFailCount("unknown-stage"); got != 0 {
		t.Errorf("unknown stage bucket=%d, want 0", got)
	}

	// 主动探测失败不得计入被动流量桶
	probeSrv := "127.0.0.1:1"
	checkUpstream(probeSrv, time.Second)
	ph := getUpstreamHealth(probeSrv)
	if ph.trafficFailsDial.Load()+ph.trafficFailsHandshake.Load()+ph.trafficFailsRequest.Load()+ph.trafficFailsWrite.Load() != 0 {
		t.Error("active probe failure must not move passive traffic failure buckets")
	}
}

// startRequestRejectUpstream 启动一个完成 SOCKS5 方法协商、但对后续
// CONNECT/UDP ASSOCIATE 请求固定回 REP=rep（非 0 即失败）的 mock 上游。
func startRequestRejectUpstream(t *testing.T, rep byte) (string, func()) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("request-reject upstream listen fail: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aErr := l.AcceptTCP()
			if aErr != nil {
				return
			}
			go func(conn *net.TCPConn) {
				defer conn.Close()
				if err := network.Sock5HandshakeBy(conn, "", ""); err != nil {
					return
				}
				req := make([]byte, 10) // IPv4 CONNECT 请求帧恰好 10 字节
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				// VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
				_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}(c)
		}
	}()
	return l.Addr().String(), func() { _ = l.Close(); wg.Wait() }
}

// TestProxyServerRequestStageFailure 验证 CONNECT 请求阶段失败（上游回
// REP=1 目标不可达）：traffic_request 计 1，其余阶段桶为 0；该失败
// 不计入健康摘除（fails=0、上游仍 alive）；会话尝试/失败口径照常入账。
func TestProxyServerRequestStageFailure(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	upstream, cleanup := startRequestRejectUpstream(t, 0x01)
	defer cleanup()

	// process_proxy_server 只在成功路径上才使用 client conn，但签名要求
	// *net.TCPConn，构造一对本地 TCP 连接传入。
	cl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client listen fail: %v", err)
	}
	defer cl.Close()
	cc, err := net.DialTCP("tcp", nil, cl.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("client dial fail: %v", err)
	}
	defer cc.Close()
	peer, err := cl.AcceptTCP()
	if err != nil {
		t.Fatalf("accept client conn fail: %v", err)
	}
	defer peer.Close()

	if process_proxy_server(context.Background(), cc, "8.8.8.8:53", upstream) {
		t.Fatal("process_proxy_server must return false on REP=1")
	}

	h := getUpstreamHealth(upstream)
	if got := h.trafficFailsRequest.Load(); got != 1 {
		t.Errorf("traffic_request=%d, want 1", got)
	}
	if h.trafficFailsDial.Load() != 0 || h.trafficFailsHandshake.Load() != 0 || h.trafficFailsWrite.Load() != 0 {
		t.Errorf("other stage buckets must stay zero: dial=%d handshake=%d write=%d",
			h.trafficFailsDial.Load(), h.trafficFailsHandshake.Load(), h.trafficFailsWrite.Load())
	}
	// 请求阶段失败不得摘除健康上游
	if h.fails.Load() != 0 {
		t.Errorf("health fails=%d, want 0 (target-unreachable must not mark dead)", h.fails.Load())
	}
	if !isServerAlive(upstream) {
		t.Error("upstream must stay alive after request-stage failure")
	}
	if h.attempts.Load() != 1 || h.connectFails.Load() != 1 {
		t.Errorf("attempts=%d connect_fails=%d, want 1/1", h.attempts.Load(), h.connectFails.Load())
	}
	if h.established.Load() != 0 {
		t.Errorf("established=%d, want 0", h.established.Load())
	}
}

func TestHealthHalfOpenCooldown(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	oldCooldown := gHealthCooldown.Load()
	cooldown := 50 * time.Millisecond
	gHealthCooldown.Store(int64(cooldown))
	t.Cleanup(func() { gHealthCooldown.Store(oldCooldown) })

	h := getUpstreamHealth("127.0.0.1:302")
	t0 := time.Now()
	if h.recordFailure(t0) {
		t.Fatal("first failure should not transition yet")
	}
	if !h.recordFailure(t0) {
		t.Fatal("second failure should transition alive -> dead")
	}

	if h.isAlive(t0) {
		t.Fatal("freshly removed server must not be alive")
	}
	if h.isAlive(t0.Add(cooldown - time.Millisecond)) {
		t.Fatal("server must stay closed before cooldown elapses")
	}
	if !h.isAlive(t0.Add(cooldown)) {
		t.Fatal("server should be half-open once cooldown elapses")
	}
	// 半开放行后，过滤逻辑也应重新纳入候选（摘除时刻放在过去以确定性模拟半开）
	halfOpen := getUpstreamHealth("127.0.0.1:399")
	past := time.Now().Add(-2 * cooldown)
	halfOpen.recordFailure(past)
	halfOpen.recordFailure(past)
	if got := filterAliveServers([]string{"127.0.0.1:399"}); len(got) != 1 {
		t.Fatalf("half-open server should be included in candidates, got %v", got)
	}
	// 冷却期内的摘除节点仍被过滤
	freshDead := getUpstreamHealth("127.0.0.1:398")
	freshDead.recordFailure(time.Now())
	freshDead.recordFailure(time.Now())
	if got := filterAliveServers([]string{"127.0.0.1:398", "127.0.0.1:397"}); len(got) != 1 || got[0] != "127.0.0.1:397" {
		t.Fatalf("freshly dead server should be filtered out, got %v", got)
	}

	// 半开试探失败：立即重新关闭并刷新摘除时刻
	t1 := t0.Add(cooldown)
	h.recordFailure(t1)
	if h.isAlive(t1) {
		t.Fatal("half-open probe failure must close the server again immediately")
	}
	if !h.isAlive(t1.Add(cooldown)) {
		t.Fatal("server should become half-open again after refreshed cooldown")
	}

	// 半开试探成功：正式恢复
	if !h.recordSuccess() {
		t.Fatal("recordSuccess should report dead -> alive transition")
	}
	if !h.isAlive(t1.Add(cooldown)) {
		t.Fatal("recovered server must be alive")
	}
}

// TestPassiveHealthTCPMarksDead 端到端验证：TCP CONNECT 经 socksfilter 转发到
// 唯一上游（拒连端口）两次后，被动反馈应把该上游标记为摘除。
func TestPassiveHealthTCPMarksDead(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	dead := "127.0.0.1:1"
	withGlobalFlags(t, dead, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	dialOnce := func() {
		c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
		if err != nil {
			t.Fatalf("dial sf fail: %v", err)
		}
		defer c.Close()
		if err := network.Sock5Handshake(c, 2000, "", ""); err != nil {
			t.Fatalf("client handshake fail: %v", err)
		}
		// 8.8.8.8 判定为需要代理；sf 先回复成功，随后向上游拨号失败并关闭连接
		_ = network.Sock5SetRequest(c, "8.8.8.8", 53, 2000)
	}
	dialOnce()
	dialOnce()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !getUpstreamHealth(dead).alive.Load() {
			return // 被动摘除成功
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead upstream was not marked removed by passive TCP failures")
}

// blackholeAddr 探测当前环境下“丢包不响应”（防火墙 DROP 语义）的地址。
// 若环境对候选地址快速拒连或无路由（容器/CI 常见），无法验证拨号超时，跳过用例避免误判。
func blackholeAddr(t *testing.T) string {
	t.Helper()
	candidates := []string{"240.0.0.1:9", "10.255.255.1:9", "192.0.2.1:9"}
	for _, addr := range candidates {
		begin := time.Now()
		c, err := dialTCPTimeout(addr, 300*time.Millisecond)
		elapsed := time.Since(begin)
		if err == nil {
			_ = c.Close()
			continue // 居然有人应答，换一个
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && elapsed >= 250*time.Millisecond {
			t.Logf("blackhole candidate %s confirmed, elapsed=%v", addr, elapsed)
			return addr
		}
	}
	t.Skip("no blackhole address available in this environment (fast reject or no route)")
	return ""
}

func TestDialTCPTimeoutSuccess(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fail: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = c.Close()
			close(accepted)
		}
	}()

	conn, err := dialTCPTimeout(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dialTCPTimeout fail: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept the dialed connection")
	}
}

func TestDialTCPTimeoutBlackhole(t *testing.T) {
	addr := blackholeAddr(t)

	begin := time.Now()
	_, err := dialTCPTimeout(addr, 300*time.Millisecond)
	elapsed := time.Since(begin)
	if err == nil {
		t.Fatal("expected dial to blackhole to fail")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
	// 既要在超时点附近返回（不能过早），也不能远超配置值（操作系统默认超时约 75s）
	if elapsed < 250*time.Millisecond {
		t.Fatalf("dial returned too fast for blackhole: %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dial timeout not honored, elapsed %v", elapsed)
	}
}

func TestDialTimeoutFlag(t *testing.T) {
	old := *dialTimeoutSec
	t.Cleanup(func() { *dialTimeoutSec = old })

	*dialTimeoutSec = 3
	if d := dialTimeout(); d != 3*time.Second {
		t.Errorf("expected 3s from flag, got %v", d)
	}
	*dialTimeoutSec = 0
	if d := dialTimeout(); d != 10*time.Second {
		t.Errorf("expected 10s fallback for zero, got %v", d)
	}
	*dialTimeoutSec = -5
	if d := dialTimeout(); d != 10*time.Second {
		t.Errorf("expected 10s fallback for negative value, got %v", d)
	}
}

// TestDialTimeoutEndToEndFailFast 端到端验证：唯一上游为黑洞地址时，客户端不会被挂到
// 操作系统级拨号超时（约 75s），而是在 -dial-timeout 附近快速收到连接关闭。
func TestDialTimeoutEndToEndFailFast(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	blackhole := blackholeAddr(t)

	oldTimeout := *dialTimeoutSec
	*dialTimeoutSec = 1 // 秒级粒度，足以快速失败
	withGlobalFlags(t, blackhole, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer func() {
		cleanupSF()
		*dialTimeoutSec = oldTimeout // 先停监听器再恢复 flag，避免 -race 数据竞争
	}()

	c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial sf fail: %v", err)
	}
	defer c.Close()
	if err := network.Sock5Handshake(c, 2000, "", ""); err != nil {
		t.Fatalf("client handshake fail: %v", err)
	}

	begin := time.Now()
	// sf 在拨号前就回了成功应答；上游拨号超时失败后它会关闭连接，客户端随后读到 EOF/reset
	_ = network.Sock5SetRequest(c, "8.8.8.8", 53, 2000)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected connection closed after upstream dial timeout")
	}
	if elapsed := time.Since(begin); elapsed > 5*time.Second {
		t.Fatalf("blackhole upstream was not failed fast, elapsed %v", elapsed)
	}
}

// relayConnPair 搭出真实的四段链路：测试持有 client、target 两个外部端，
// relClient、relTarget 是各自对端（accepted 端），交给 relay 转发。
// 这样读 relay 两端的只有 relay 自己，测试通过外部端收发，不存在并发抢读。
func relayConnPair(t *testing.T) (client, target, relClient, relTarget *net.TCPConn) {
	t.Helper()
	dialOne := func() (dialer, accepted *net.TCPConn) {
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("listen fail: %v", err)
		}
		acceptedCh := make(chan *net.TCPConn, 1)
		go func() {
			a, acceptErr := ln.AcceptTCP()
			if acceptErr == nil {
				acceptedCh <- a
			}
		}()
		d, err := net.DialTCP("tcp", nil, mustTCPAddr(t, ln.Addr().String()))
		if err != nil {
			t.Fatalf("dial fail: %v", err)
		}
		a := <-acceptedCh
		_ = ln.Close()
		return d, a
	}
	client, relClient = dialOne()
	target, relTarget = dialOne()
	t.Cleanup(func() {
		_ = client.Close()
		_ = target.Close()
		_ = relClient.Close()
		_ = relTarget.Close()
	})
	return
}

// withIdleFlag 设置 -idle-timeout（秒），返回恢复函数。必须在启动 relay 前设置。
func withIdleFlag(t *testing.T, sec int) {
	t.Helper()
	old := *idleTimeoutSec
	*idleTimeoutSec = sec
	t.Cleanup(func() { *idleTimeoutSec = old })
}

func TestRelayIdleTimeoutClosesSilent(t *testing.T) {
	withIdleFlag(t, 1)
	client, _, relClient, relTarget := relayConnPair(t)

	done := make(chan struct{})
	go func() {
		relay(context.Background(), relClient, relTarget, nil, nil)
		close(done)
	}()

	// 双向静默：约一个 idle 周期后 relay 应主动关闭两端
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected silent relay connection to be closed by idle timeout")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not exit after idle timeout")
	}
}

func TestRelayIdleTimeoutTrafficKeepsAlive(t *testing.T) {
	withIdleFlag(t, 1)
	client, target, relClient, relTarget := relayConnPair(t)

	// target 侧 echo 服务：读到什么写回什么，读到 FIN 则关闭，让 relay 另一方向正常收尾
	var echoWg sync.WaitGroup
	echoWg.Add(1)
	go func() {
		defer echoWg.Done()
		_, _ = io.Copy(target, target)
		_ = target.Close()
	}()

	done := make(chan struct{})
	go func() {
		relay(context.Background(), relClient, relTarget, nil, nil)
		close(done)
	}()

	ping := []byte("ping")
	buf := make([]byte, len(ping))
	begin := time.Now()
	// 持续 8 轮、每轮 300ms（总长 > 2 个 idle 周期）：有流量期间绝不能被掐断
	for i := 0; i < 8; i++ {
		if _, err := client.Write(ping); err != nil {
			t.Fatalf("round %d write ping: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatalf("round %d read pong: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if d := time.Since(begin); d < 2*time.Second {
		t.Fatalf("keepalive phase too short (%v) to prove the timer resets", d)
	}

	// 停流量后应在一个 idle 周期左右关闭
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected relay to close after both directions went silent")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not exit after traffic stopped")
	}
	echoWg.Wait()
}

func TestRelayIdleTimeoutDisabled(t *testing.T) {
	withIdleFlag(t, 0)
	client, target, relClient, relTarget := relayConnPair(t)

	var echoWg sync.WaitGroup
	echoWg.Add(1)
	go func() {
		defer echoWg.Done()
		_, _ = io.Copy(target, target)
		_ = target.Close()
	}()

	done := make(chan struct{})
	go func() {
		relay(context.Background(), relClient, relTarget, nil, nil)
		close(done)
	}()

	pingPong := func(tag string) {
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatalf("%s write: %v", tag, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
			t.Fatalf("%s read: %v", tag, err)
		}
	}
	pingPong("before sleep")
	// 静默远超任何假设的默认 idle 周期，连接必须仍然存活
	time.Sleep(1500 * time.Millisecond)
	pingPong("after sleep")

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not exit after client close")
	}
	echoWg.Wait()
}

func TestRelayIdleTimeoutFlag(t *testing.T) {
	old := *idleTimeoutSec
	oldDial := *dialTimeoutSec
	t.Cleanup(func() {
		*idleTimeoutSec = old
		*dialTimeoutSec = oldDial
	})

	*dialTimeoutSec = 0 // 确保两个超时语义互不干扰
	*idleTimeoutSec = 0
	if d := relayIdleTimeout(); d != 0 {
		t.Errorf("expected idle disabled for 0, got %v", d)
	}
	*idleTimeoutSec = 5
	if d := relayIdleTimeout(); d != 5*time.Second {
		t.Errorf("expected 5s from flag, got %v", d)
	}
	*idleTimeoutSec = -3
	if d := relayIdleTimeout(); d != 0 {
		t.Errorf("expected 0 (disabled) for negative, got %v", d)
	}
}

func TestRelayCancelForceCloses(t *testing.T) {
	withIdleFlag(t, 0) // 关掉空闲超时，证明连接关闭只由 ctx 取消触发
	client, _, relClient, relTarget := relayConnPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		relay(ctx, relClient, relTarget, nil, nil)
		close(done)
	}()

	// 连接静默存活 300ms，不能自己断
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := client.Read(make([]byte, 4)); err == nil {
		t.Fatal("unexpected data on silent connection")
	}

	cancel() // 模拟排空窗口结束强制关闭

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected client connection closed after ctx cancel")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not exit after ctx cancel")
	}
}

// startEchoTCP 启动本地回显服务器，返回地址与清理函数。
func startEchoTCP(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("echo listen fail: %v", err)
	}
	var wg sync.WaitGroup
	// acceptDone 保证清理时接受循环已退出（不会再有 wg.Add），
	// 之后再 wg.Wait，消除 Add/Wait 与 goroutine 泄漏导致的数据竞争。
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn *net.TCPConn) {
				defer wg.Done()
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-acceptDone
		wg.Wait()
	}
}

// socksConnectTo 以 SOCKS5 客户端身份连接 sf 并请求 CONNECT target，返回已就绪的隧道。
func socksConnectTo(t *testing.T, sfAddr, target string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(c, 2000, "", ""); err != nil {
		_ = c.Close()
		t.Fatalf("client handshake fail: %v", err)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		_ = c.Close()
		t.Fatalf("bad target %s: %v", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = c.Close()
		t.Fatalf("bad port %s: %v", portStr, err)
	}
	if err := network.Sock5SetRequest(c, host, port, 2000); err != nil {
		_ = c.Close()
		t.Fatalf("connect request fail: %v", err)
	}
	return c
}

// serveTestEnv 用 serve 拉起一个真实 sf 监听器（走 gConnWg 跟踪），
// 返回地址、两个取消函数（停止接受/强制关闭）与等待 serve 退出的函数。
func serveTestEnv(t *testing.T) (sfAddr string, stopAccept, forceDrain func(), waitServe func()) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sf listen fail: %v", err)
	}
	sigCtx, cancelSig := context.WithCancel(context.Background())
	drainCtx, cancelDrain := context.WithCancel(context.Background())

	// 与 main 行为一致：停止接受信号到达后关闭 listener，解除 AcceptTCP 阻塞。
	go func() {
		<-sigCtx.Done()
		_ = ln.Close()
	}()

	serveDone := make(chan struct{})
	go func() {
		serve(sigCtx, drainCtx, ln)
		close(serveDone)
	}()

	t.Cleanup(func() {
		cancelSig()
		cancelDrain()
		_ = ln.Close()
		gConnWg.Wait() // 防止全局 WaitGroup 残留连接影响后续用例
	})
	return ln.Addr().String(), cancelSig, cancelDrain, func() {
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Fatal("serve did not exit after stopping listener")
		}
	}
}

func TestServeGracefulDrainTimeout(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, stopAccept, forceDrain, waitServe := serveTestEnv(t)

	client := socksConnectTo(t, sfAddr, echoAddr)
	defer client.Close()

	pingPong := func(tag string) {
		if _, err := client.Write([]byte("hi")); err != nil {
			t.Fatalf("%s write: %v", tag, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
			t.Fatalf("%s read: %v", tag, err)
		}
	}
	pingPong("before shutdown")

	stopAccept()
	waitServe() // listener 已停，连接仍在排空窗口内

	// grace 窗口内存量连接数据照常转发
	pingPong("during grace")

	begin := time.Now()
	if waitForDrain(800 * time.Millisecond) {
		t.Fatal("drain should time out while connection stays open")
	}
	if d := time.Since(begin); d < 700*time.Millisecond {
		t.Fatalf("waitForDrain returned before grace period: %v", d)
	}

	forceDrain() // 排空窗口结束，强制关闭

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected client connection force closed after drain")
	}

	drained := make(chan struct{})
	go func() {
		gConnWg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight connection goroutines did not exit after force drain")
	}
}

func TestServeGracefulDrainNatural(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, stopAccept, _, waitServe := serveTestEnv(t)

	client := socksConnectTo(t, sfAddr, echoAddr)

	stopAccept()
	waitServe()

	// 客户端在信号后很快主动断开，存量连接自然结束，不应等满 grace 窗口
	_ = client.Close()
	begin := time.Now()
	if !waitForDrain(5 * time.Second) {
		t.Fatal("drain should complete naturally after client closed")
	}
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("natural drain took too long: %v", d)
	}
}

func TestShutdownTimeoutFlag(t *testing.T) {
	old := *shutdownTimeoutSec
	t.Cleanup(func() { *shutdownTimeoutSec = old })

	*shutdownTimeoutSec = 15
	if d := shutdownTimeout(); d != 15*time.Second {
		t.Errorf("expected 15s from flag, got %v", d)
	}
	*shutdownTimeoutSec = 0
	if d := shutdownTimeout(); d != 0 {
		t.Errorf("expected 0 (no wait) for zero, got %v", d)
	}
	*shutdownTimeoutSec = -2
	if d := shutdownTimeout(); d != 0 {
		t.Errorf("expected 0 for negative, got %v", d)
	}
}

// startUDPEcho 启动本地回显 UDP 服务，返回连接与停止函数。
func startUDPEcho(t *testing.T) (*net.UDPConn, func()) {
	t.Helper()
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("echo UDP listen fail: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], src)
		}
	}()
	return echoConn, func() {
		_ = echoConn.Close()
		wg.Wait()
	}
}

// udpAssocEnv 建立一条到 sf 的 UDP ASSOCIATE，返回控制 TCP、客户端 UDP 与 relay 地址。
// 调用方负责关闭 clientUDP；控制 TCP 在空闲回收场景下由服务端关闭。
func udpAssocEnv(t *testing.T, sfAddr string) (*net.TCPConn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	clientTCP, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("client dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(clientTCP, 2000, "", ""); err != nil {
		_ = clientTCP.Close()
		t.Fatalf("handshake fail: %v", err)
	}
	bnd, err := network.Sock5SetUDPRequest(clientTCP, "0.0.0.0", 0, 2000)
	if err != nil {
		_ = clientTCP.Close()
		t.Fatalf("SetUDPRequest fail: %v", err)
	}
	relayUDPAddr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		_ = clientTCP.Close()
		t.Fatalf("ResolveUDPAddr fail: %v", err)
	}
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = clientTCP.Close()
		t.Fatalf("client UDP listen fail: %v", err)
	}
	t.Cleanup(func() { _ = clientUDP.Close() })
	return clientTCP, clientUDP, relayUDPAddr
}

// udpRoundtrip 经 sf relay 向 echo 发一个包并读回显，用于证明关联存活且双向通路正常。
func udpRoundtrip(t *testing.T, clientUDP *net.UDPConn, relayAddr, echoAddr *net.UDPAddr) {
	t.Helper()
	payload := []byte("udp-idle-keepalive")
	pkt, err := network.Sock5PackUDP(echoAddr.IP.String(), echoAddr.Port, payload)
	if err != nil {
		t.Fatalf("PackUDP fail: %v", err)
	}
	if _, err := clientUDP.WriteToUDP(pkt, relayAddr); err != nil {
		t.Fatalf("WriteToUDP fail: %v", err)
	}
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read echo via relay fail: %v", err)
	}
	_, _, data, err := network.Sock5UnpackUDP(buf[:n])
	if err != nil || string(data) != string(payload) {
		t.Fatalf("bad echo packet: %q err=%v", data, err)
	}
}

// tcpClosed reports whether the peer has closed the TCP connection.
func tcpClosed(t *testing.T, c *net.TCPConn, wait time.Duration) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	_, err := c.Read(make([]byte, 1))
	return err != nil
}

func withUDPIdleFlag(t *testing.T, sec int) {
	t.Helper()
	old := *udpIdleTimeoutSec
	*udpIdleTimeoutSec = sec
	t.Cleanup(func() { *udpIdleTimeoutSec = old })
}

func TestUDPIdleTimeoutClosesSilent(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 1)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()

	// 先打一个包激活关联（建立直连套接字），随后完全静默
	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	// 双向静默超过 idle（1s）+ tick 间隔（200ms）后，服务端应关闭控制 TCP
	if !tcpClosed(t, clientTCP, 3*time.Second) {
		t.Fatal("expected silent udp association control tcp to be closed by idle timeout")
	}
}

func TestUDPIdleTimeoutTrafficKeepsAlive(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 1)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	// 每 300ms 一轮收发，持续 ~2.7s（跨越两个以上 idle 周期）：关联绝不能被回收
	begin := time.Now()
	for i := 0; i < 9; i++ {
		udpRoundtrip(t, clientUDP, relayAddr, echoAddr)
		time.Sleep(300 * time.Millisecond)
	}
	if d := time.Since(begin); d < 2*time.Second {
		t.Fatalf("keepalive phase too short (%v) to prove timer resets", d)
	}
	// 持续收发期间控制连接必须仍然存活：静默半秒读到的只应是 deadline 超时
	_ = clientTCP.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, aliveErr := clientTCP.Read(make([]byte, 1))
	if aliveErr == nil {
		t.Fatal("unexpected data on udp control tcp")
	}
	var ne net.Error
	if !errors.As(aliveErr, &ne) || !ne.Timeout() {
		t.Fatalf("control tcp closed during active traffic: %v", aliveErr)
	}

	// 停止流量后应在一个 idle 周期左右被回收
	if !tcpClosed(t, clientTCP, 3*time.Second) {
		t.Fatal("expected association reaped after traffic stopped")
	}
}

func TestUDPIdleTimeoutDisabled(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 0)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()

	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	// 静默远超任何 idle 周期，控制连接必须仍然存活
	time.Sleep(1500 * time.Millisecond)
	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))
}

func TestUDPIdleTimeoutFlag(t *testing.T) {
	old := *udpIdleTimeoutSec
	t.Cleanup(func() { *udpIdleTimeoutSec = old })

	*udpIdleTimeoutSec = 60
	if d := udpIdleTimeout(); d != 60*time.Second {
		t.Errorf("expected 60s from flag, got %v", d)
	}
	*udpIdleTimeoutSec = 0
	if d := udpIdleTimeout(); d != 0 {
		t.Errorf("expected 0 (disabled) for zero, got %v", d)
	}
	*udpIdleTimeoutSec = -4
	if d := udpIdleTimeout(); d != 0 {
		t.Errorf("expected 0 for negative, got %v", d)
	}
}

// tcpKeepaliveIdleOpt 返回当前平台 TCP keepalive 空闲时长的 getsockopt 选项，
// 不支持的平台返回 false。darwin 为 TCP_KEEPALIVE，linux 为 TCP_KEEPIDLE（单位均为秒）。
func tcpKeepaliveIdleOpt() (int, bool) {
	switch runtime.GOOS {
	case "darwin":
		return 0x10, true // TCP_KEEPALIVE
	case "linux":
		return 0x4, true // TCP_KEEPIDLE
	default:
		return 0, false
	}
}

func getTCPSockoptInt(t *testing.T, c *net.TCPConn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn fail: %v", err)
	}
	var val int
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		val, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, opt)
	}); err != nil {
		t.Fatalf("Control fail: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("GetsockoptInt(%d) fail: %v", opt, sockErr)
	}
	return val
}

// keepaliveIdleSockopt 读取内核 keepalive 空闲秒数；不支持的平台跳过。
func keepaliveIdleSockopt(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	opt, ok := tcpKeepaliveIdleOpt()
	if !ok {
		t.Skipf("keepalive sockopt unsupported on %s", runtime.GOOS)
	}
	return getTCPSockoptInt(t, c, opt)
}

// assertKeepaliveEnabled 校验 keepalive 已按 idleSec 启用。
// 注意 darwin 的 getsockopt(SO_KEEPALIVE) 恒定返回 8（平台 quirk），
// 只能通过 TCP_KEEPALIVE 空闲值与 TCP_KEEPINTVL 间隔值侧面验证。
func assertKeepaliveEnabled(t *testing.T, c *net.TCPConn, idleSecs int) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		rc, err := c.SyscallConn()
		if err != nil {
			t.Fatalf("SyscallConn fail: %v", err)
		}
		var enabled int
		if err := rc.Control(func(fd uintptr) {
			enabled, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		}); err != nil {
			t.Fatalf("Control fail: %v", err)
		}
		if enabled != 1 {
			t.Errorf("expected SO_KEEPALIVE=1, got %d", enabled)
		}
		if got := keepaliveIdleSockopt(t, c); got != idleSecs {
			t.Errorf("expected keepalive idle %ds, got %d", idleSecs, got)
		}
	case "darwin":
		if got := keepaliveIdleSockopt(t, c); got != idleSecs {
			t.Errorf("expected TCP_KEEPALIVE idle %ds, got %d", idleSecs, got)
		}
		// interval = ceil(idle/3)（Go setsockopt 对秒向上取整：5s/3 -> 2s）；TCP_KEEPINTVL
		wantInterval := (idleSecs + 2) / 3
		if got := getTCPSockoptInt(t, c, 0x101); got != wantInterval {
			t.Errorf("expected TCP_KEEPINTVL %ds, got %d", wantInterval, got)
		}
	default:
		t.Skipf("keepalive assertion unsupported on %s", runtime.GOOS)
	}
}

func withTCPKeepaliveFlag(t *testing.T, sec int) {
	t.Helper()
	old := *tcpKeepaliveSec
	*tcpKeepaliveSec = sec
	t.Cleanup(func() { *tcpKeepaliveSec = old })
}

func TestTCPKeepaliveFlag(t *testing.T) {
	old := *tcpKeepaliveSec
	t.Cleanup(func() { *tcpKeepaliveSec = old })

	*tcpKeepaliveSec = 45
	if d := tcpKeepaliveIdle(); d != 45*time.Second {
		t.Errorf("expected 45s from flag, got %v", d)
	}
	*tcpKeepaliveSec = 0
	if d := tcpKeepaliveIdle(); d != 0 {
		t.Errorf("expected 0 (disabled) for zero, got %v", d)
	}
	*tcpKeepaliveSec = -9
	if d := tcpKeepaliveIdle(); d != 0 {
		t.Errorf("expected 0 for negative, got %v", d)
	}
}

func TestEnableTCPKeepAliveApplied(t *testing.T) {
	withTCPKeepaliveFlag(t, 5)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fail: %v", err)
	}
	defer ln.Close()

	connected := make(chan *net.TCPConn, 1)
	go func() {
		c, _ := ln.AcceptTCP()
		connected <- c
	}()

	dialed, err := dialTCPTimeout(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	defer dialed.Close()
	accepted := <-connected
	defer accepted.Close()

	// 拨出路径（上游/直连）在 dialTCPTimeout 内已设置
	assertKeepaliveEnabled(t, dialed, 5)
	// 服务端接受路径同样设置
	enableTCPKeepAlive(accepted)
	assertKeepaliveEnabled(t, accepted, 5)
}

func TestEnableTCPKeepAliveEcho(t *testing.T) {
	withTCPKeepaliveFlag(t, 3)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fail: %v", err)
	}
	defer ln.Close()
	acceptedCh := make(chan *net.TCPConn, 1)
	go func() {
		c, _ := ln.AcceptTCP()
		acceptedCh <- c
	}()

	c, err := dialTCPTimeout(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	defer c.Close()
	accepted := <-acceptedCh
	defer accepted.Close()
	enableTCPKeepAlive(accepted) // 在主 goroutine 设置，避免与 flag cleanup 竞争
	go func() {
		_, _ = io.Copy(accepted, accepted)
		_ = accepted.Close()
	}()

	// 设置 keepalive 不得影响正常收发
	if _, err := c.Write([]byte("ka")); err != nil {
		t.Fatalf("write fail: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatalf("echo read fail after keepalive enabled: %v", err)
	}
}

// readKeepaliveSwitch 返回 SO_KEEPALIVE 开关位；各内核启用值不同（linux=1，
// darwin=8），故调用方只按「0=关 / 非0=开」判定。
func readKeepaliveSwitch(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn fail: %v", err)
	}
	var enabled int
	if err := rc.Control(func(fd uintptr) {
		enabled, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); err != nil {
		t.Fatalf("Control fail: %v", err)
	}
	return enabled
}

func TestTCPKeepaliveDisabledLeavesSocket(t *testing.T) {
	if _, supported := tcpKeepaliveIdleOpt(); !supported {
		t.Skipf("keepalive sockopt check unsupported on %s", runtime.GOOS)
	}
	withTCPKeepaliveFlag(t, 0)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fail: %v", err)
	}
	defer ln.Close()
	acceptSide := make(chan int, 1)
	go func() {
		c, _ := ln.AcceptTCP()
		if c != nil {
			// flag=0：两条路径都必须显式关闭。Go 零值 Dialer 会在拨出侧默认
			// 开启 keepalive；darwin 上 accept 侧系统默认也是开启的。
			enableTCPKeepAlive(c)
			acceptSide <- readKeepaliveSwitch(t, c)
			_ = c.Close()
		}
	}()

	// dialTCPTimeout 内部也会调用 enableTCPKeepAlive
	c, err := dialTCPTimeout(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	defer c.Close()
	if got := <-acceptSide; got != 0 {
		t.Errorf("accepted conn: expected SO_KEEPALIVE=0 when disabled, got %d", got)
	}
	// 等 accept goroutine 读完 flag 后再允许 cleanup 恢复，避免数据竞争
	if got := readKeepaliveSwitch(t, c); got != 0 {
		t.Errorf("dialed conn: expected SO_KEEPALIVE=0 when disabled, got %d", got)
	}
}

// ---- 运行时统计 /stats ----

type counterSnapshot struct {
	activeTCP      int64
	totalTCP       int64
	activeUDP      int64
	totalUDP       int64
	clientToTarget int64
	targetToClient int64
}

func snapshotCounters() counterSnapshot {
	return counterSnapshot{
		activeTCP:      gActiveTCPConns.Load(),
		totalTCP:       gTotalTCPConns.Load(),
		activeUDP:      gActiveUDPAssoc.Load(),
		totalUDP:       gTotalUDPAssoc.Load(),
		clientToTarget: gBytesClientToTarget.Load(),
		targetToClient: gBytesTargetToClient.Load(),
	}
}

// waitFor 轮询条件直到满足或超时，用于等待异步 relay/计数器更新。
func waitFor(t *testing.T, desc string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", timeout, desc)
}

func TestStatsDefaultDisabled(t *testing.T) {
	if *statsAddr != "" {
		t.Errorf("stats-addr should be empty/disabled by default, got %q", *statsAddr)
	}
}

func TestStatsTCPAndByteCounters(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	before := snapshotCounters()
	client := socksConnectTo(t, sfAddr, echoAddr)
	defer client.Close()

	// 连接建立后活跃数 +1、累计数 +1
	waitFor(t, "active tcp conn counted", 3*time.Second, func() bool {
		s := snapshotCounters()
		return s.activeTCP-before.activeTCP >= 1 && s.totalTCP-before.totalTCP >= 1
	})

	// echo：上行 N 字节、下行 N 字节；字节计数在该方向 io.Copy 结束（收到 FIN）后入账
	payload := bytes.Repeat([]byte("x"), 1234)
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload fail: %v", err)
	}
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo fail: %v", err)
	}
	_ = client.Close()

	waitFor(t, "tcp conn released after close", 3*time.Second, func() bool {
		s := snapshotCounters()
		return s.activeTCP == before.activeTCP && s.totalTCP-before.totalTCP >= 1
	})
	s := snapshotCounters()
	if d := s.clientToTarget - before.clientToTarget; d < int64(len(payload)) {
		t.Errorf("client_to_target bytes delta %d, want >= %d", d, len(payload))
	}
	if d := s.targetToClient - before.targetToClient; d < int64(len(payload)) {
		t.Errorf("target_to_client bytes delta %d, want >= %d", d, len(payload))
	}
}

func TestStatsUDPCounter(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 0)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	before := snapshotCounters()
	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)

	waitFor(t, "active udp assoc counted", 3*time.Second, func() bool {
		s := snapshotCounters()
		return s.activeUDP-before.activeUDP >= 1 && s.totalUDP-before.totalUDP >= 1
	})

	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	_ = clientTCP.Close()
	waitFor(t, "udp assoc released after control tcp close", 3*time.Second, func() bool {
		s := snapshotCounters()
		return s.activeUDP == before.activeUDP && s.totalUDP-before.totalUDP >= 1
	})
}

func TestStatsHTTPEndpoint(t *testing.T) {
	gStartTime.Store(time.Now().Add(-5 * time.Minute).UnixNano()) // 让 uptime 行稳定非 0
	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start stats server fail: %v", err)
	}
	defer stop()

	resp, err := http.Get("http://" + addr + "/stats")
	if err != nil {
		t.Fatalf("GET /stats fail: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body fail: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"socksfilter " + version,
		"uptime:",
		"tcp_connections: active=",
		"udp_associations: active=",
		"tcp_relay_bytes: client_to_target=",
		"route_relay_bytes(tcp+udp payload): direct_c2t=",
		"route_sessions(tcp+udp): direct_active=",
		"dns_lookups: literal=",
		"idle_timeout_closed: tcp=",
		"entry_errors: handshake=",
		"upstreams:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stats body missing %q\n--- body ---\n%s", want, text)
		}
	}

	// 配置中的上游必须逐个列出，且状态字段存在
	for _, srv := range strings.Fields(*servers) {
		wantLine := "  " + srv + ": state="
		if !strings.Contains(text, wantLine) {
			t.Errorf("stats body missing upstream line %q", wantLine)
		}
	}

	// HEAD 无 body 但可探测；POST 拒绝
	headResp, err := http.Head("http://" + addr + "/stats")
	if err != nil {
		t.Fatalf("HEAD fail: %v", err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD expected 200, got %d", headResp.StatusCode)
	}

	postResp, err := http.Post("http://"+addr+"/stats", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST fail: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST expected 405, got %d", postResp.StatusCode)
	}
}

func TestStatsUpstreamStates(t *testing.T) {
	resetUpstreamHealth()
	now := time.Now()

	// 默认全部 alive
	if !strings.Contains(renderStats(now), "state=alive") {
		t.Fatal("expected freshly reset upstream to render alive")
	}

	// 构造摘除状态：连续失败到阈值。冷却时间拉长到 1h，刚摘除时 isAlive=false -> dead
	oldCooldown := gHealthCooldown.Load()
	gHealthCooldown.Store(int64(time.Hour))
	t.Cleanup(func() { gHealthCooldown.Store(oldCooldown) })

	srv := strings.Fields(*servers)[0]
	h := getUpstreamHealth(srv)
	for i := int64(0); i < healthFailThreshold; i++ {
		h.recordFailure(now)
	}
	rendered := renderStats(now)
	if !strings.Contains(rendered, srv+": state=dead") {
		t.Fatalf("expected dead state for %s, body:\n%s", srv, rendered)
	}
	if !strings.Contains(rendered, "removed_since=") {
		t.Fatal("expected removed_since on dead upstream")
	}

	// 冷却已过 -> half_open
	gHealthCooldown.Store(int64(time.Second))
	if !strings.Contains(renderStats(now.Add(time.Hour)), srv+": state=half_open") {
		t.Fatal("expected half_open after cooldown elapsed")
	}
}

// ---- -max-conn 并发会话上限 ----

func withMaxConnFlag(t *testing.T, n int) {
	t.Helper()
	old := *maxConn
	*maxConn = n
	t.Cleanup(func() { *maxConn = old })
}

// dialSocks5Raw 建立到 sf 的裸 TCP 并完成无认证 SOCKS5 握手，
// 返回的连接由调用方关闭；用于构造预期被拒绝的 CONNECT/UDP ASSOCIATE 请求。
func dialSocks5Raw(t *testing.T, sfAddr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(c, 2000, "", ""); err != nil {
		_ = c.Close()
		t.Fatalf("client handshake fail: %v", err)
	}
	return c
}

// tcpEchoOnce 通过已建立的 SOCKS5 隧道收发一小段数据，证明隧道可用。
func tcpEchoOnce(t *testing.T, tag string, c *net.TCPConn) {
	t.Helper()
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatalf("%s write: %v", tag, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatalf("%s read echo: %v", tag, err)
	}
}

func TestMaxConnFlagDefault(t *testing.T) {
	if *maxConn != 0 {
		t.Fatalf("max-conn should default to 0 (disabled), got %d", *maxConn)
	}
	if !admitSession() {
		t.Fatal("admitSession must always admit when max-conn is disabled")
	}
}

// TestMaxConnRejectsOverflowAndRecovers 端到端验证：上限为 1 时，占用中的会话
// 拒绝新会话（SOCKS5 REP=0x01）并累计 rejected；会话释放后名额恢复可再接入。
func TestMaxConnRejectsOverflowAndRecovers(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)
	withMaxConnFlag(t, 1)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	before := snapshotCounters()
	beforeRejected := gRejectedConns.Load()

	// A 占用唯一名额并保持隧道打开
	a := socksConnectTo(t, sfAddr, echoAddr)
	tcpEchoOnce(t, "accepted session", a)

	// B 必须被失败应答拒绝（REP=0x01 -> general failure），而非裸 TCP 关闭
	b := dialSocks5Raw(t, sfAddr)
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("bad echo addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("bad echo port: %v", err)
	}
	reqErr := network.Sock5SetRequest(b, host, port, 2000)
	_ = b.Close()
	if reqErr == nil {
		t.Fatal("expected overflow session to be rejected, got success")
	}
	if !strings.Contains(reqErr.Error(), "general failure") {
		t.Fatalf("expected SOCKS5 general failure reply, got: %v", reqErr)
	}

	// 拒绝计数 +1；B 的处理 goroutine 退出后活跃数回落为 before+1（仅剩 A）
	waitFor(t, "rejected counter incremented", 3*time.Second, func() bool {
		return gRejectedConns.Load()-beforeRejected >= 1
	})
	waitFor(t, "rejected session slot released", 3*time.Second, func() bool {
		return gActiveTCPConns.Load() == before.activeTCP+1
	})
	if text := renderStats(time.Now()); !strings.Contains(text,
		fmt.Sprintf("rejected=%d", beforeRejected+1)) {
		t.Fatalf("stats missing rejected=%d:\n%s", beforeRejected+1, text)
	}

	// A 释放后名额恢复，C 正常接入
	_ = a.Close()
	waitFor(t, "active count back to baseline after held session closes", 3*time.Second,
		func() bool { return gActiveTCPConns.Load() == before.activeTCP })

	c := socksConnectTo(t, sfAddr, echoAddr)
	defer c.Close()
	tcpEchoOnce(t, "session admitted after slot released", c)
}

// TestMaxConnIncludesUDPAssociate 验证 UDP ASSOCIATE 与 TCP CONNECT 共用同一份名额：
// 名额被占满时，UDP 关联请求同样收到失败应答。
func TestMaxConnIncludesUDPAssociate(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)
	withMaxConnFlag(t, 1)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	held := socksConnectTo(t, sfAddr, echoAddr)
	defer held.Close()

	c := dialSocks5Raw(t, sfAddr)
	defer c.Close()
	if _, err := network.Sock5SetUDPRequest(c, "0.0.0.0", 0, 2000); err == nil {
		t.Fatal("expected udp associate rejected while max-conn reached")
	} else if !strings.Contains(err.Error(), "general failure") {
		t.Fatalf("expected SOCKS5 general failure reply, got: %v", err)
	}
}

// TestMaxConnDisabledAllowsConcurrent 验证上限为 0（关闭）时多条并发会话全部放行。
func TestMaxConnDisabledAllowsConcurrent(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)
	withMaxConnFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	const n = 4
	conns := make([]*net.TCPConn, 0, n)
	for i := 0; i < n; i++ {
		conns = append(conns, socksConnectTo(t, sfAddr, echoAddr))
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(idx int, tunnel *net.TCPConn) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("session-%d", idx))
			if _, err := tunnel.Write(msg); err != nil {
				t.Errorf("session %d write: %v", idx, err)
				return
			}
			_ = tunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(tunnel, buf); err != nil {
				t.Errorf("session %d read echo: %v", idx, err)
				return
			}
			if string(buf) != string(msg) {
				t.Errorf("session %d echo mismatch: %q", idx, buf)
			}
		}(i, c)
	}
	wg.Wait()
}

// ---- 探针端点 /healthz /readyz ----

func TestHealthzEndpoint(t *testing.T) {
	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start observability server fail: %v", err)
	}
	defer stop()

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz fail: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("expected body ok, got %q", body)
	}

	// HEAD 返回头但无 body；POST 拒绝
	headResp, err := http.Head("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("HEAD /healthz fail: %v", err)
	}
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD expected 200, got %d", headResp.StatusCode)
	}

	postResp, err := http.Post("http://"+addr+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /healthz fail: %v", err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST expected 405, got %d", postResp.StatusCode)
	}
}

func TestReadyzEndpoint(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)
	// 拉长冷却，保证摘除后 isAlive=false，不进入半开
	oldCooldown := gHealthCooldown.Load()
	gHealthCooldown.Store(int64(time.Hour))
	t.Cleanup(func() { gHealthCooldown.Store(oldCooldown) })

	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start observability server fail: %v", err)
	}
	defer stop()

	getReadyz := func() (int, string) {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz fail: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// 初始所有上游存活 -> 200 ready
	if code, body := getReadyz(); code != http.StatusOK || !strings.Contains(body, "ready") {
		t.Fatalf("expected 200 ready with alive upstreams, got %d %q", code, body)
	}

	// 全部上游连续失败到阈值 -> 摘除 -> 503 not ready
	configured := strings.Fields(*servers)
	now := time.Now()
	for _, srv := range configured {
		h := getUpstreamHealth(srv)
		for i := 0; i < healthFailThreshold; i++ {
			h.recordFailure(now)
		}
	}
	if code, body := getReadyz(); code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "not ready") || !strings.Contains(body, fmt.Sprintf("%d upstreams", len(configured))) {
		t.Fatalf("expected 503 not ready with all dead, got %d %q", code, body)
	}

	// 任一上游恢复 -> 重新就绪，body 给出存活/摘除计数
	getUpstreamHealth(configured[0]).recordSuccess()
	if code, body := getReadyz(); code != http.StatusOK ||
		!strings.Contains(body, fmt.Sprintf("alive=1 dead=%d", len(configured)-1)) {
		t.Fatalf("expected 200 with alive=1, got %d %q", code, body)
	}
}

// TestReadyzUpstreamDetails 验证就绪探针响应体的上游明细：全部摘除时逐上游
// 列 state=dead；冷却期满进入半开后探针重新就绪，汇总 half_open 计数正确，
// 明细行出现 state=half_open 与 removed_since；HEAD 只返回状态码无响应体。
func TestReadyzUpstreamDetails(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)
	oldCooldown := gHealthCooldown.Load()
	gHealthCooldown.Store(int64(time.Hour))
	t.Cleanup(func() { gHealthCooldown.Store(oldCooldown) })

	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start observability server fail: %v", err)
	}
	defer stop()

	configured := strings.Fields(*servers)
	now := time.Now()
	for _, srv := range configured {
		h := getUpstreamHealth(srv)
		for i := 0; i < healthFailThreshold; i++ {
			h.recordFailure(now)
		}
	}

	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz fail: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
	text := string(body)
	if want := fmt.Sprintf("all %d upstreams are dead (alive=0 half_open=0 total=%d)", len(configured), len(configured)); !strings.Contains(text, want) {
		t.Fatalf("summary line missing %q: %q", want, text)
	}
	// 每个上游都应列出明细行
	for _, srv := range configured {
		if !strings.Contains(text, "  "+srv+": state=dead removed_since=") {
			t.Errorf("missing dead detail line for %s: %q", srv, text)
		}
	}

	// 冷却期满：摘除最久的第一个上游进入半开（deadAt 最早）
	gHealthCooldown.Store(0)
	resp2, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz fail: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("half-open upstream must make readiness 200, got %d", resp2.StatusCode)
	}
	text2 := string(body2)
	// cooldown=0 后全部摘除上游均进入半开
	if want := fmt.Sprintf("alive=0 dead=0 half_open=%d total=%d", len(configured), len(configured)); !strings.Contains(text2, want) {
		t.Fatalf("half-open summary missing %q: %q", want, text2)
	}
	for _, srv := range configured {
		if !strings.Contains(text2, "  "+srv+": state=half_open removed_since=") {
			t.Errorf("missing half_open detail line for %s: %q", srv, text2)
		}
	}

	// HEAD：状态码随就绪状态返回，但无响应体
	headResp, err := http.Head("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("HEAD /readyz fail: %v", err)
	}
	headBody, _ := io.ReadAll(headResp.Body)
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD expected 200, got %d", headResp.StatusCode)
	}
	if len(headBody) != 0 {
		t.Errorf("HEAD body must be empty, got %q", headBody)
	}

	// POST 拒绝
	postResp, err := http.Post("http://"+addr+"/readyz", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /readyz fail: %v", err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST expected 405, got %d", postResp.StatusCode)
	}
}

// TestReadyzNoUpstreamsConfigured 验证未配置任何上游时就绪探针返回 503。
func TestReadyzNoUpstreamsConfigured(t *testing.T) {
	oldServers := *servers
	*servers = ""
	t.Cleanup(func() { *servers = oldServers })

	if alive, dead := readinessSummary(time.Now()); alive != 0 || dead != 0 {
		t.Fatalf("expected 0/0 for empty upstream list, got alive=%d dead=%d", alive, dead)
	}

	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start observability server fail: %v", err)
	}
	defer stop()
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz fail: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no upstreams, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "no upstreams configured") {
		t.Fatalf("unexpected body: %q", body)
	}
}

// ---- 每上游流量计数 attempts / established / connect_fails ----

// proxyRequestOnce 通过 sf 发起一次到 8.8.8.8:53（必然走代理）的 CONNECT，
// sf 会先回成功再尝试上游；返回的隧道由调用方关闭。
func proxyRequestOnce(t *testing.T, sfAddr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial sf fail: %v", err)
	}
	if err := network.Sock5Handshake(c, 2000, "", ""); err != nil {
		_ = c.Close()
		t.Fatalf("client handshake fail: %v", err)
	}
	if err := network.Sock5SetRequest(c, "8.8.8.8", 53, 2000); err != nil {
		_ = c.Close()
		t.Fatalf("client SetRequest fail: %v", err)
	}
	return c
}

func TestUpstreamCountersTCPFailures(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	dead := "127.0.0.1:1"
	withGlobalFlags(t, dead, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	c1 := proxyRequestOnce(t, sfAddr)
	_ = c1.Close()
	c2 := proxyRequestOnce(t, sfAddr)
	_ = c2.Close()

	// attempts 在入口入账、connect_fails 在失败返回后的 defer 入账，
	// 必须等待终态条件，不能只等 attempts（第二次拨号可能尚在途）。
	h := getUpstreamHealth(dead)
	waitFor(t, "dead upstream failure counters settled", 3*time.Second, func() bool {
		return h.attempts.Load() == 2 && h.connectFails.Load() == 2
	})
	if h.established.Load() != 0 {
		t.Errorf("expected established=0, got %d", h.established.Load())
	}
}

func TestUpstreamCountersTCPSuccess(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	echoAddr, cleanupEcho := startEchoTCP(t)
	t.Cleanup(cleanupEcho)
	// 无认证的 mock 上游：忽略客户端请求的目标，固定转发到 echo
	upstreamAddr, cleanupUp := startAuthConnectUpstream(t, "", "", echoAddr)
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	client := proxyRequestOnce(t, sfAddr)
	if _, err := client.Write([]byte("counter-ping")); err != nil {
		t.Fatalf("write fail: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "counter-ping" {
		t.Fatalf("expected echo via upstream, got n=%d err=%v", n, err)
	}

	h := getUpstreamHealth(upstreamAddr)
	if h.attempts.Load() != 1 {
		t.Errorf("expected attempts=1, got %d", h.attempts.Load())
	}
	if h.established.Load() != 1 {
		t.Errorf("expected established=1, got %d", h.established.Load())
	}
	if h.connectFails.Load() != 0 {
		t.Errorf("expected connect_fails=0, got %d", h.connectFails.Load())
	}
	_ = client.Close()
}

// TestUpstreamCountersUDPSessionReuse 验证 UDP 同一目标多个包只建立一次上游会话：
// attempts=1、established=1，复用不计数。
func TestUpstreamCountersUDPSessionReuse(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	upstreamAddr, pktCount, cleanupUp := startMockUDPRelay(t, "c:", "", "")
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()

	// 同一目标连发 3 个包
	for i := 0; i < 3; i++ {
		pkt, err := network.Sock5PackUDP("8.8.8.8", 53, []byte(fmt.Sprintf("p%d", i)))
		if err != nil {
			t.Fatalf("PackUDP fail: %v", err)
		}
		if _, err := clientUDP.WriteToUDP(pkt, relayAddr); err != nil {
			t.Fatalf("WriteToUDP fail: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 2048)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("read reply %d fail: %v", i, err)
		}
		if _, _, data, err := network.Sock5UnpackUDP(respBuf[:n]); err != nil ||
			!strings.HasPrefix(string(data), "c:") {
			t.Fatalf("bad reply %d: %q err=%v", i, data, err)
		}
	}

	if pktCount.Load() != 3 {
		t.Fatalf("expected upstream to receive 3 packets, got %d", pktCount.Load())
	}
	h := getUpstreamHealth(upstreamAddr)
	if h.attempts.Load() != 1 {
		t.Errorf("expected attempts=1 (single session), got %d", h.attempts.Load())
	}
	if h.established.Load() != 1 {
		t.Errorf("expected established=1, got %d", h.established.Load())
	}
	if h.connectFails.Load() != 0 {
		t.Errorf("expected connect_fails=0, got %d", h.connectFails.Load())
	}
}

// ---- v0.7.6 按出口归因的中继字节统计（TCP/UDP × direct/upstream）----

// TestRouteBytesTCPDirect 验证 TCP 直连流量只计入 direct 桶，双向有效载荷精确归因。
func TestRouteBytesTCPDirect(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	beforeC2T := gRouteBytesDirectC2T.Load()
	beforeT2C := gRouteBytesDirectT2C.Load()

	client := socksConnectTo(t, sfAddr, echoAddr)
	payload := bytes.Repeat([]byte("d"), 1000)
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload fail: %v", err)
	}
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo fail: %v", err)
	}
	_ = client.Close()

	// 两个方向的 io.Copy 在收到 FIN 后入账，等待终态精确相等。
	want := int64(len(payload))
	waitFor(t, "direct tcp route bytes settled", 3*time.Second, func() bool {
		return gRouteBytesDirectC2T.Load() == beforeC2T+want &&
			gRouteBytesDirectT2C.Load() == beforeT2C+want
	})
}

// TestRouteBytesTCPProxy 验证经上游的 TCP 流量计入该上游的字节桶，
// 直连桶保持不变，且 SOCKS5 握手字节不被计入（只计隧道内有效载荷）。
func TestRouteBytesTCPProxy(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	echoAddr, cleanupEcho := startEchoTCP(t)
	t.Cleanup(cleanupEcho)
	upstreamAddr, cleanupUp := startAuthConnectUpstream(t, "", "", echoAddr)
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	directBeforeC2T := gRouteBytesDirectC2T.Load()
	directBeforeT2C := gRouteBytesDirectT2C.Load()

	payload := []byte("route-bytes-ping!!") // 18 字节
	client := proxyRequestOnce(t, sfAddr)
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write fail: %v", err)
	}
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo fail: %v", err)
	}
	_ = client.Close()

	h := getUpstreamHealth(upstreamAddr)
	want := int64(len(payload))
	waitFor(t, "upstream tcp route bytes settled", 3*time.Second, func() bool {
		return h.bytesC2T.Load() == want && h.bytesT2C.Load() == want
	})
	if gRouteBytesDirectC2T.Load() != directBeforeC2T || gRouteBytesDirectT2C.Load() != directBeforeT2C {
		t.Errorf("direct counters must stay unchanged via upstream route: c2t %d->%d t2c %d->%d",
			directBeforeC2T, gRouteBytesDirectC2T.Load(), directBeforeT2C, gRouteBytesDirectT2C.Load())
	}
}

// TestRouteBytesUDPDirect 验证 UDP 直连数据报按解包后的有效载荷归因到 direct 桶。
func TestRouteBytesUDPDirect(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 0)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	beforeC2T := gRouteBytesDirectC2T.Load()
	beforeT2C := gRouteBytesDirectT2C.Load()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()

	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	want := int64(len("udp-idle-keepalive"))
	waitFor(t, "direct udp route bytes settled", 3*time.Second, func() bool {
		return gRouteBytesDirectC2T.Load() == beforeC2T+want &&
			gRouteBytesDirectT2C.Load() == beforeT2C+want
	})
}

// TestRouteBytesUDPProxy 验证经上游的 UDP 数据报按 payload 归因：
// SOCKS5 封装头不计入；回包 payload 由 mock 加 2 字节前缀，双向分别核验。
func TestRouteBytesUDPProxy(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	const prefix = "r:"
	upstreamAddr, pktCount, cleanupUp := startMockUDPRelay(t, prefix, "", "")
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	directBeforeC2T := gRouteBytesDirectC2T.Load()
	directBeforeT2C := gRouteBytesDirectT2C.Load()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()

	payloads := [][]byte{[]byte("ab"), []byte("cdef")} // 上行合计 6 字节
	var wantC2T, wantT2C int64
	for _, p := range payloads {
		pkt, err := network.Sock5PackUDP("8.8.8.8", 53, p)
		if err != nil {
			t.Fatalf("PackUDP fail: %v", err)
		}
		if _, err := clientUDP.WriteToUDP(pkt, relayAddr); err != nil {
			t.Fatalf("WriteToUDP fail: %v", err)
		}
		wantC2T += int64(len(p))
		wantT2C += int64(len(p) + len(prefix)) // mock 回包为 prefix + data
	}
	for i := 0; i < len(payloads); i++ {
		_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 2048)
		if _, _, err := clientUDP.ReadFromUDP(respBuf); err != nil {
			t.Fatalf("read reply %d fail: %v", i, err)
		}
	}

	h := getUpstreamHealth(upstreamAddr)
	waitFor(t, "upstream udp route bytes settled", 3*time.Second, func() bool {
		return h.bytesC2T.Load() == wantC2T && h.bytesT2C.Load() == wantT2C
	})
	if pktCount.Load() != int64(len(payloads)) {
		t.Fatalf("upstream packet count=%d, want %d", pktCount.Load(), len(payloads))
	}
	if gRouteBytesDirectC2T.Load() != directBeforeC2T || gRouteBytesDirectT2C.Load() != directBeforeT2C {
		t.Errorf("direct counters must stay unchanged via upstream route: c2t %d->%d t2c %d->%d",
			directBeforeC2T, gRouteBytesDirectC2T.Load(), directBeforeT2C, gRouteBytesDirectT2C.Load())
	}
}

// TestRouteSessionsTCPDirect 验证 TCP 直连隧道生命周期内 direct 出口
// 活跃会话 +1、累计 +1，隧道关闭后活跃数回落，累计保留。
func TestRouteSessionsTCPDirect(t *testing.T) {
	init_env()
	withIdleFlag(t, 0)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	beforeActive := gRouteSessionsActiveDirect.Load()
	beforeTotal := gRouteSessionsTotalDirect.Load()

	client := socksConnectTo(t, sfAddr, echoAddr)
	payload := []byte("route-session-direct")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload fail: %v", err)
	}
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo fail: %v", err)
	}

	waitFor(t, "direct tcp session active", 3*time.Second, func() bool {
		return gRouteSessionsActiveDirect.Load() == beforeActive+1 &&
			gRouteSessionsTotalDirect.Load() == beforeTotal+1
	})

	_ = client.Close()
	waitFor(t, "direct tcp session reaped", 3*time.Second, func() bool {
		return gRouteSessionsActiveDirect.Load() == beforeActive
	})
	if gRouteSessionsTotalDirect.Load() != beforeTotal+1 {
		t.Errorf("direct total sessions=%d, want %d", gRouteSessionsTotalDirect.Load(), beforeTotal+1)
	}
}

// TestRouteSessionsTCPProxy 验证经上游建立的 TCP 隧道计入该上游活跃/累计，
// direct 桶不变；关闭后上游活跃数回落。
func TestRouteSessionsTCPProxy(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	echoAddr, cleanupEcho := startEchoTCP(t)
	t.Cleanup(cleanupEcho)
	upstreamAddr, cleanupUp := startAuthConnectUpstream(t, "", "", echoAddr)
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	directBeforeActive := gRouteSessionsActiveDirect.Load()
	directBeforeTotal := gRouteSessionsTotalDirect.Load()

	payload := []byte("route-session-up!!")
	client := proxyRequestOnce(t, sfAddr)
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write fail: %v", err)
	}
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo fail: %v", err)
	}

	h := getUpstreamHealth(upstreamAddr)
	waitFor(t, "upstream tcp session active", 3*time.Second, func() bool {
		return h.sessionsActive.Load() == 1 && h.established.Load() == 1
	})

	_ = client.Close()
	waitFor(t, "upstream tcp session reaped", 3*time.Second, func() bool {
		return h.sessionsActive.Load() == 0
	})
	if gRouteSessionsActiveDirect.Load() != directBeforeActive || gRouteSessionsTotalDirect.Load() != directBeforeTotal {
		t.Errorf("direct session counters must stay unchanged via upstream route: active %d->%d total %d->%d",
			directBeforeActive, gRouteSessionsActiveDirect.Load(), directBeforeTotal, gRouteSessionsTotalDirect.Load())
	}
}

// TestRouteSessionsUDPDirect 验证 UDP 直连套接字建立后 direct 出口会话计数，
// 关联关闭（控制 TCP 断开）后活跃数回落。
func TestRouteSessionsUDPDirect(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 0)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	beforeActive := gRouteSessionsActiveDirect.Load()
	beforeTotal := gRouteSessionsTotalDirect.Load()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	waitFor(t, "direct udp session active", 3*time.Second, func() bool {
		return gRouteSessionsActiveDirect.Load() == beforeActive+1 &&
			gRouteSessionsTotalDirect.Load() == beforeTotal+1
	})

	_ = clientTCP.Close()
	waitFor(t, "direct udp session reaped", 3*time.Second, func() bool {
		return gRouteSessionsActiveDirect.Load() == beforeActive
	})
	if gRouteSessionsTotalDirect.Load() != beforeTotal+1 {
		t.Errorf("direct total sessions=%d, want %d", gRouteSessionsTotalDirect.Load(), beforeTotal+1)
	}
}

// TestRouteSessionsUDPProxy 验证 UDP 上游会话计入该上游活跃/累计，direct 桶不变；
// 关联关闭时 closeOnce 路径保证活跃数恰好减一次。
func TestRouteSessionsUDPProxy(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	upstreamAddr, _, cleanupUp := startMockUDPRelay(t, "r:", "", "")
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	directBeforeActive := gRouteSessionsActiveDirect.Load()
	directBeforeTotal := gRouteSessionsTotalDirect.Load()

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)

	pkt, err := network.Sock5PackUDP("8.8.8.8", 53, []byte("ab"))
	if err != nil {
		t.Fatalf("PackUDP fail: %v", err)
	}
	if _, err := clientUDP.WriteToUDP(pkt, relayAddr); err != nil {
		t.Fatalf("WriteToUDP fail: %v", err)
	}
	_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 2048)
	if _, _, err := clientUDP.ReadFromUDP(respBuf); err != nil {
		t.Fatalf("read upstream reply fail: %v", err)
	}

	h := getUpstreamHealth(upstreamAddr)
	waitFor(t, "upstream udp session active", 3*time.Second, func() bool {
		return h.sessionsActive.Load() == 1 && h.established.Load() == 1
	})

	_ = clientTCP.Close()
	waitFor(t, "upstream udp session reaped", 3*time.Second, func() bool {
		return h.sessionsActive.Load() == 0
	})
	if gRouteSessionsActiveDirect.Load() != directBeforeActive || gRouteSessionsTotalDirect.Load() != directBeforeTotal {
		t.Errorf("direct session counters must stay unchanged via upstream route: active %d->%d total %d->%d",
			directBeforeActive, gRouteSessionsActiveDirect.Load(), directBeforeTotal, gRouteSessionsTotalDirect.Load())
	}
}

// TestDNSResolveObservability 验证 resolveRouteIP 的 DNS 观测埋点：
// IP 字面量目标计入 literal；host/root 两级缓存命中计入 cache_hit。
// 仅使用无网络路径，保证用例确定可复现。
func TestDNSResolveObservability(t *testing.T) {
	init_env()

	beforeLiteral := gDNSLookupsLiteral.Load()
	beforeCacheHit := gDNSLookupsCacheHit.Load()
	beforeResolved := gDNSLookupsResolved.Load()
	beforeFailure := gDNSLookupsFailure.Load()

	// 1) IP 字面量：不查缓存/网络
	ip, ok := resolveRouteIP("1.2.3.4", "1.2.3.4")
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("literal resolve = %q,%v", ip, ok)
	}

	// 2) host 精确缓存命中
	gDnsCache.Set("dns-obs-host.example.com", "5.6.7.8")
	ip, ok = resolveRouteIP("dns-obs-host.example.com", "dns-obs-host.example.com")
	if !ok || ip != "5.6.7.8" {
		t.Fatalf("host cache resolve = %q,%v", ip, ok)
	}

	// 3) root 域缓存命中（子域名未单独缓存）
	gDnsCache.Set("dns-obs-root.example.net", "9.10.11.12")
	ip, ok = resolveRouteIP("www.dns-obs-root.example.net", "dns-obs-root.example.net")
	if !ok || ip != "9.10.11.12" {
		t.Fatalf("root cache resolve = %q,%v", ip, ok)
	}

	if got := gDNSLookupsLiteral.Load(); got != beforeLiteral+1 {
		t.Errorf("literal lookups=%d, want +1 (before %d)", got, beforeLiteral)
	}
	if got := gDNSLookupsCacheHit.Load(); got != beforeCacheHit+2 {
		t.Errorf("cache_hit lookups=%d, want +2 (before %d)", got, beforeCacheHit)
	}
	if got := gDNSLookupsResolved.Load(); got != beforeResolved {
		t.Errorf("resolved lookups=%d, want unchanged %d", got, beforeResolved)
	}
	if got := gDNSLookupsFailure.Load(); got != beforeFailure {
		t.Errorf("failure lookups=%d, want unchanged %d", got, beforeFailure)
	}
}

// TestDNSObservabilityProxyLiteralE2E 验证真实代理会话对 IP 目标做分流判定时
// 计入一次 literal lookup（8.8.8.8:53 无需 DNS）。
func TestDNSObservabilityProxyLiteralE2E(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	echoAddr, cleanupEcho := startEchoTCP(t)
	t.Cleanup(cleanupEcho)
	upstreamAddr, cleanupUp := startAuthConnectUpstream(t, "", "", echoAddr)
	t.Cleanup(cleanupUp)

	withGlobalFlags(t, upstreamAddr, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	before := gDNSLookupsLiteral.Load()
	client := proxyRequestOnce(t, sfAddr)
	_ = client.Close()

	waitFor(t, "literal dns lookup counted", 3*time.Second, func() bool {
		return gDNSLookupsLiteral.Load() == before+1
	})
}

// TestStatsRendersUpstreamCounters 验证 /stats 文本包含每上游的累计字段，
// 包括 v0.7.6 的按出口归因字节、v0.7.7 的按出口归因会话，以及 direct 汇总行。
func TestStatsRendersUpstreamCounters(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	// direct 桶是进程级累计量（跨用例不清零），写入固定值后验证渲染与上游行。
	srv0 := strings.Fields(*servers)[0]
	directC2T := gRouteBytesDirectC2T.Load()
	directT2C := gRouteBytesDirectT2C.Load()
	gRouteBytesDirectC2T.Store(4321)
	gRouteBytesDirectT2C.Store(8765)
	t.Cleanup(func() {
		gRouteBytesDirectC2T.Store(directC2T)
		gRouteBytesDirectT2C.Store(directT2C)
	})
	getUpstreamHealth(srv0).bytesC2T.Store(111)
	getUpstreamHealth(srv0).bytesT2C.Store(222)
	getUpstreamHealth(srv0).sessionsActive.Store(7)
	getUpstreamHealth(srv0).probeAttempts.Store(60)
	getUpstreamHealth(srv0).probeFails.Store(6)
	getUpstreamHealth(srv0).probeLastNS.Store(1_500_000) // 1.5ms
	getUpstreamHealth(srv0).probeSumNS.Store(6_000_000)  // avg 0.1ms over 60 probes
	getUpstreamHealth(srv0).markedDead.Store(3)
	getUpstreamHealth(srv0).recovered.Store(2)
	getUpstreamHealth(srv0).trafficFailsDial.Store(9)
	getUpstreamHealth(srv0).trafficFailsHandshake.Store(4)
	getUpstreamHealth(srv0).trafficFailsRequest.Store(7)
	getUpstreamHealth(srv0).trafficFailsWrite.Store(1)
	directSessActive := gRouteSessionsActiveDirect.Load()
	directSessTotal := gRouteSessionsTotalDirect.Load()
	gRouteSessionsActiveDirect.Store(21)
	gRouteSessionsTotalDirect.Store(42)
	t.Cleanup(func() {
		gRouteSessionsActiveDirect.Store(directSessActive)
		gRouteSessionsTotalDirect.Store(directSessTotal)
	})

	text := renderStats(time.Now())
	for _, srv := range strings.Fields(*servers) {
		prefix := "  " + srv + ":"
		line := ""
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, prefix) {
				line = l
				break
			}
		}
		if line == "" {
			t.Fatalf("missing upstream line for %s", srv)
		}
		wants := []string{"attempts=0", "established=0", "connect_fails=0", "bytes_c2t=0", "bytes_t2c=0", "sessions_active=0", "probe_attempts=0", "probe_fails=0", "probe_last_ms=0.000", "probe_avg_ms=0.000", "marked_dead=0", "recovered=0", "traffic_dial=0", "traffic_handshake=0", "traffic_request=0", "traffic_write=0"}
		if srv == srv0 {
			wants[3] = "bytes_c2t=111"
			wants[4] = "bytes_t2c=222"
			wants[5] = "sessions_active=7"
			wants[6] = "probe_attempts=60"
			wants[7] = "probe_fails=6"
			wants[8] = "probe_last_ms=1.500"
			wants[9] = "probe_avg_ms=0.100"
			wants[10] = "marked_dead=3"
			wants[11] = "recovered=2"
			wants[12] = "traffic_dial=9"
			wants[13] = "traffic_handshake=4"
			wants[14] = "traffic_request=7"
			wants[15] = "traffic_write=1"
		}
		for _, want := range wants {
			if !strings.Contains(line, want) {
				t.Errorf("upstream line missing %s: %s", want, line)
			}
		}
	}
	if !strings.Contains(text, "direct_c2t=4321 direct_t2c=8765") {
		t.Errorf("stats text missing direct route totals:\n%s", text)
	}
	if !strings.Contains(text, "route_sessions(tcp+udp): direct_active=21 direct_total=42") {
		t.Errorf("stats text missing direct route sessions:\n%s", text)
	}
}

// TestIdleClosedTCPCounter 验证 TCP 隧道双向静默超过 -idle-timeout 被回收时
// gIdleClosedTCP 恰好 +1；有数据交互期间不计，正常关闭也不计。
func TestIdleClosedTCPCounter(t *testing.T) {
	init_env()
	withIdleFlag(t, 1)

	echoAddr, cleanupEcho := startEchoTCP(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	client := socksConnectTo(t, sfAddr, echoAddr)
	ping := []byte("idle-count-ping")
	if _, err := client.Write(ping); err != nil {
		t.Fatalf("write ping fail: %v", err)
	}
	pong := make([]byte, len(ping))
	if _, err := io.ReadFull(client, pong); err != nil {
		t.Fatalf("read pong fail: %v", err)
	}

	before := gIdleClosedTCP.Load()
	// 此后双向静默，约一个 idle 周期后隧道应被服务端主动关闭并计数。
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected silent tunnel closed by idle timeout")
	}
	waitFor(t, "tcp idle close counted", 5*time.Second, func() bool {
		return gIdleClosedTCP.Load() == before+1
	})
}

// TestIdleClosedUDPCounter 验证 UDP 关联双向静默超过 -udp-idle-timeout 被回收时
// gIdleClosedUDP 恰好 +1。
func TestIdleClosedUDPCounter(t *testing.T) {
	init_env()
	withUDPIdleFlag(t, 1)

	echoConn, cleanupEcho := startUDPEcho(t)
	defer cleanupEcho()
	sfAddr, _, _, _ := serveTestEnv(t)

	clientTCP, clientUDP, relayAddr := udpAssocEnv(t, sfAddr)
	defer clientTCP.Close()
	udpRoundtrip(t, clientUDP, relayAddr, echoConn.LocalAddr().(*net.UDPAddr))

	before := gIdleClosedUDP.Load()
	if !tcpClosed(t, clientTCP, 3*time.Second) {
		t.Fatal("expected silent udp association control tcp closed by idle timeout")
	}
	waitFor(t, "udp idle close counted", 3*time.Second, func() bool {
		return gIdleClosedUDP.Load() == before+1
	})
}

// withLocalAuth 临时开启 SOCKS5 入口用户名/密码认证，测试结束自动还原。
func withLocalAuth(t *testing.T, user, pass string) {
	t.Helper()
	oldUser, oldPass := *username, *password
	*username, *password = user, pass
	t.Cleanup(func() { *username, *password = oldUser, oldPass })
}

// TestEntryErrorHandshakeCounter 验证开启本地认证后，错误凭据握手失败计一次
// handshake 入口错误。注意：auth flag 是普通 *string，必须在启动监听器之前设置，
// 否则与 process goroutine 的无锁读取构成数据竞争。
func TestEntryErrorHandshakeCounter(t *testing.T) {
	withLocalAuth(t, "obs-user", "obs-pass")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	before := gEntryErrHandshake.Load()
	c, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	if err := network.Sock5Handshake(c, 2000, "obs-user", "wrong-pass"); err == nil {
		t.Fatal("expected handshake failure with wrong password")
	}
	_ = c.Close()
	waitFor(t, "handshake error counted", 3*time.Second, func() bool {
		return gEntryErrHandshake.Load() == before+1
	})
}

// TestEntryErrorBadRequestAndUnsupportedCmd 验证握手通过后的两类入口错误：
// 残缺请求帧计 bad_request；BIND（0x02）收到 0x07 应答并计 unsupported_command。
func TestEntryErrorBadRequestAndUnsupportedCmd(t *testing.T) {
	sfAddr, cleanupSF := startSocksfilterListener(t)
	defer cleanupSF()

	// 1) 畸形请求：方法协商通过后只发 2 字节残缺请求帧再关闭
	beforeBad := gEntryErrBadRequest.Load()
	c2, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	if err := network.Sock5Handshake(c2, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}
	if _, err := c2.Write([]byte{0x05, 0x01}); err != nil {
		t.Fatalf("write truncated request fail: %v", err)
	}
	_ = c2.Close()
	waitFor(t, "bad request counted", 3*time.Second, func() bool {
		return gEntryErrBadRequest.Load() == beforeBad+1
	})

	// 2) 不支持的命令（BIND=0x02）：应收到 0x07 失败应答并计数
	beforeCmd := gEntryErrUnsupportedCmd.Load()
	c3, err := net.DialTCP("tcp", nil, mustTCPAddr(t, sfAddr))
	if err != nil {
		t.Fatalf("dial fail: %v", err)
	}
	if err := network.Sock5Handshake(c3, 2000, "", ""); err != nil {
		t.Fatalf("handshake fail: %v", err)
	}
	if _, err := c3.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write bind request fail: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c3, rep); err != nil {
		t.Fatalf("read bind reply fail: %v", err)
	}
	if rep[1] != 0x07 {
		t.Fatalf("expected command-not-supported reply 0x07, got %#x", rep[1])
	}
	_ = c3.Close()
	waitFor(t, "unsupported command counted", 3*time.Second, func() bool {
		return gEntryErrUnsupportedCmd.Load() == beforeCmd+1
	})
}

// TestStatsRendersDNSCounters 验证 /stats 的两行 DNS 指标按计数器现值渲染。
func TestStatsRendersDNSCounters(t *testing.T) {
	saved := [6]int64{
		gDNSLookupsLiteral.Load(), gDNSLookupsCacheHit.Load(), gDNSLookupsResolved.Load(),
		gDNSLookupsFailure.Load(), gDNSResolveSmart.Load(), gDNSResolveFallback.Load(),
	}
	gDNSLookupsLiteral.Store(101)
	gDNSLookupsCacheHit.Store(202)
	gDNSLookupsResolved.Store(303)
	gDNSLookupsFailure.Store(4)
	gDNSResolveSmart.Store(250)
	gDNSResolveFallback.Store(53)
	t.Cleanup(func() {
		gDNSLookupsLiteral.Store(saved[0])
		gDNSLookupsCacheHit.Store(saved[1])
		gDNSLookupsResolved.Store(saved[2])
		gDNSLookupsFailure.Store(saved[3])
		gDNSResolveSmart.Store(saved[4])
		gDNSResolveFallback.Store(saved[5])
	})

	text := renderStats(time.Now())
	for _, want := range []string{
		"dns_lookups: literal=101 cache_hit=202 resolved=303 failure=4",
		"dns_resolved_source: smart_resolver=250 system_fallback=53 cache_entries=",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stats text missing %q:\n%s", want, text)
		}
	}
}

// TestStatsRendersIdleCounters 验证 /stats 的空闲回收行按计数器现值渲染。
func TestStatsRendersIdleCounters(t *testing.T) {
	beforeTCP := gIdleClosedTCP.Load()
	beforeUDP := gIdleClosedUDP.Load()
	gIdleClosedTCP.Store(31)
	gIdleClosedUDP.Store(17)
	t.Cleanup(func() {
		gIdleClosedTCP.Store(beforeTCP)
		gIdleClosedUDP.Store(beforeUDP)
	})

	text := renderStats(time.Now())
	if !strings.Contains(text, "idle_timeout_closed: tcp=31 udp=17") {
		t.Errorf("stats text missing idle counters:\n%s", text)
	}
}

// TestStatsRendersEntryErrors 验证 /stats 的入口错误行按计数器现值渲染。
func TestStatsRendersEntryErrors(t *testing.T) {
	saved := [3]int64{gEntryErrHandshake.Load(), gEntryErrBadRequest.Load(), gEntryErrUnsupportedCmd.Load()}
	gEntryErrHandshake.Store(41)
	gEntryErrBadRequest.Store(5)
	gEntryErrUnsupportedCmd.Store(2)
	t.Cleanup(func() {
		gEntryErrHandshake.Store(saved[0])
		gEntryErrBadRequest.Store(saved[1])
		gEntryErrUnsupportedCmd.Store(saved[2])
	})

	text := renderStats(time.Now())
	if !strings.Contains(text, "entry_errors: handshake=41 bad_request=5 unsupported_command=2") {
		t.Errorf("stats text missing entry error counters:\n%s", text)
	}
}

// ---- Prometheus /metrics ----

// validPromMetricName 校验指标名满足 Prometheus 词法 [a-zA-Z_:][a-zA-Z0-9_:]*。
func validPromMetricName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || r == ':':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func TestPrometheusMetricsEndpoint(t *testing.T) {
	addr, stop, err := startStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start stats server fail: %v", err)
	}
	defer stop()

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics fail: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("expected prometheus content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// 所有指标族都必须声明正确的类型
	for name, typ := range map[string]string{
		"socksfilter_build_info":                                  "gauge",
		"socksfilter_tcp_connections_active":                      "gauge",
		"socksfilter_tcp_connections_total":                       "counter",
		"socksfilter_tcp_connections_rejected_total":              "counter",
		"socksfilter_udp_associations_active":                     "gauge",
		"socksfilter_udp_associations_total":                      "counter",
		"socksfilter_tcp_relay_bytes_total":                       "counter",
		"socksfilter_relay_bytes_total":                           "counter",
		"socksfilter_route_sessions_active":                       "gauge",
		"socksfilter_route_sessions_total":                        "counter",
		"socksfilter_dns_lookups_total":                           "counter",
		"socksfilter_dns_resolutions_total":                       "counter",
		"socksfilter_dns_cache_entries":                           "gauge",
		"socksfilter_idle_timeout_closed_total":                   "counter",
		"socksfilter_entry_errors_total":                          "counter",
		"socksfilter_max_connections":                             "gauge",
		"socksfilter_upstream_up":                                 "gauge",
		"socksfilter_upstream_health_state":                       "gauge",
		"socksfilter_upstream_consecutive_failures":               "gauge",
		"socksfilter_upstream_session_attempts_total":             "counter",
		"socksfilter_upstream_sessions_established_total":         "counter",
		"socksfilter_upstream_connect_failures_total":             "counter",
		"socksfilter_upstream_health_probes_total":                "counter",
		"socksfilter_upstream_health_probe_last_duration_seconds": "gauge",
		"socksfilter_upstream_health_probe_duration_seconds":      "histogram",
		"socksfilter_upstream_health_transitions_total":           "counter",
		"socksfilter_upstream_traffic_failures_total":             "counter",
	} {
		if !strings.Contains(text, "# TYPE "+name+" "+typ) {
			t.Errorf("missing TYPE declaration for %s %s", name, typ)
		}
	}

	// 每个样本行必须是 name[{labels}] value 形式
	samples := 0
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		samples++
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			t.Errorf("malformed metric line: %q", line)
			continue
		}
		name, labels, ok := strings.Cut(line[:sp], "{")
		if ok {
			if !strings.HasSuffix(labels, "}") {
				t.Errorf("malformed labels on line: %q", line)
			}
		}
		if !validPromMetricName(name) {
			t.Errorf("invalid metric name %q on line: %q", name, line)
		}
		if line[sp+1:] == "" {
			t.Errorf("missing value on line: %q", line)
		}
	}
	if samples < 123 {
		t.Fatalf("expected >=123 metric samples, got %d", samples)
	}
	if want := "socksfilter_build_info{version=\"" + version + "\"} 1"; !strings.Contains(text, want) {
		t.Errorf("missing build info sample %q", want)
	}

	// HEAD：有头无体
	headResp, err := http.Head("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("HEAD /metrics fail: %v", err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK || headResp.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("unexpected HEAD response: %d %q", headResp.StatusCode, headResp.Header.Get("Content-Type"))
	}

	// 其他方法 405
	postResp, err := http.Post("http://"+addr+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /metrics fail: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", postResp.StatusCode)
	}
}

func TestPrometheusMetricsUpstreamCounters(t *testing.T) {
	init_env()
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	dead := "127.0.0.1:1"
	withGlobalFlags(t, dead, "", "")
	sfAddr, cleanupSF := startSocksfilterListener(t)
	t.Cleanup(cleanupSF)

	// 需要连续 healthFailThreshold 次失败才会摘除上游
	for i := 0; i < healthFailThreshold; i++ {
		c := proxyRequestOnce(t, sfAddr)
		_ = c.Close()
	}

	h := getUpstreamHealth(dead)
	waitFor(t, "dead upstream counters settled", 3*time.Second, func() bool {
		return h.attempts.Load() == healthFailThreshold && h.connectFails.Load() == healthFailThreshold
	})

	text := renderPrometheusMetrics(time.Now())
	label := `{upstream="` + dead + `"}`
	for _, want := range []string{
		"socksfilter_upstream_up" + label + " 0",
		fmt.Sprintf("socksfilter_upstream_session_attempts_total%s %d", label, healthFailThreshold),
		"socksfilter_upstream_sessions_established_total" + label + " 0",
		fmt.Sprintf("socksfilter_upstream_connect_failures_total%s %d", label, healthFailThreshold),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// TestPrometheusMetricsRouteBytes 验证 per-route 中继字节指标：direct 两个方向
// 恒输出；每个上游各输出两个方向，且数值取自对应计数器。
func TestPrometheusMetricsRouteBytes(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv0 := strings.Fields(*servers)[0]
	directC2T := gRouteBytesDirectC2T.Load()
	directT2C := gRouteBytesDirectT2C.Load()
	gRouteBytesDirectC2T.Store(300)
	gRouteBytesDirectT2C.Store(400)
	t.Cleanup(func() {
		gRouteBytesDirectC2T.Store(directC2T)
		gRouteBytesDirectT2C.Store(directT2C)
	})
	getUpstreamHealth(srv0).bytesC2T.Store(500)
	getUpstreamHealth(srv0).bytesT2C.Store(600)

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_relay_bytes_total counter") {
		t.Fatal("missing TYPE declaration for socksfilter_relay_bytes_total")
	}
	for _, want := range []string{
		`socksfilter_relay_bytes_total{route="direct",direction="client_to_target"} 300`,
		`socksfilter_relay_bytes_total{route="direct",direction="target_to_client"} 400`,
		fmt.Sprintf(`socksfilter_relay_bytes_total{route=%q,direction="client_to_target"} 500`, srv0),
		fmt.Sprintf(`socksfilter_relay_bytes_total{route=%q,direction="target_to_client"} 600`, srv0),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// 其余未承载流量的上游也必须输出零值样本
	for _, srv := range strings.Fields(*servers) {
		if srv == srv0 {
			continue
		}
		for _, dir := range []string{"client_to_target", "target_to_client"} {
			want := fmt.Sprintf(`socksfilter_relay_bytes_total{route=%q,direction=%q} 0`, srv, dir)
			if !strings.Contains(text, want) {
				t.Errorf("metrics output missing zero sample %q", want)
			}
		}
	}
}

// TestPrometheusMetricsRouteSessions 验证 per-route 会话指标：direct 活跃/累计
// 恒输出；每上游输出活跃 gauge 与累计（取 established）；其余上游为零值样本。
func TestPrometheusMetricsRouteSessions(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv0 := strings.Fields(*servers)[0]
	directActive := gRouteSessionsActiveDirect.Load()
	directTotal := gRouteSessionsTotalDirect.Load()
	gRouteSessionsActiveDirect.Store(21)
	gRouteSessionsTotalDirect.Store(42)
	t.Cleanup(func() {
		gRouteSessionsActiveDirect.Store(directActive)
		gRouteSessionsTotalDirect.Store(directTotal)
	})
	h0 := getUpstreamHealth(srv0)
	h0.sessionsActive.Store(7)
	h0.established.Store(9)
	t.Cleanup(func() {
		h0.sessionsActive.Store(0)
		h0.established.Store(0)
	})

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_route_sessions_active gauge") {
		t.Error("missing TYPE declaration for socksfilter_route_sessions_active")
	}
	if !strings.Contains(text, "# TYPE socksfilter_route_sessions_total counter") {
		t.Error("missing TYPE declaration for socksfilter_route_sessions_total")
	}
	for _, want := range []string{
		`socksfilter_route_sessions_active{route="direct"} 21`,
		`socksfilter_route_sessions_total{route="direct"} 42`,
		fmt.Sprintf(`socksfilter_route_sessions_active{route=%q} 7`, srv0),
		fmt.Sprintf(`socksfilter_route_sessions_total{route=%q} 9`, srv0),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// 其余未承载流量的上游也必须输出零值样本
	for _, srv := range strings.Fields(*servers) {
		if srv == srv0 {
			continue
		}
		for _, want := range []string{
			fmt.Sprintf(`socksfilter_route_sessions_active{route=%q} 0`, srv),
			fmt.Sprintf(`socksfilter_route_sessions_total{route=%q} 0`, srv),
		} {
			if !strings.Contains(text, want) {
				t.Errorf("metrics output missing zero sample %q", want)
			}
		}
	}
}

// TestPrometheusMetricsDNSCounters 验证 DNS 三个指标族：lookup 四种结果、
// resolution 两种来源、cache_entries gauge，数值取自对应计数器。
func TestPrometheusMetricsDNSCounters(t *testing.T) {
	saved := [6]int64{
		gDNSLookupsLiteral.Load(), gDNSLookupsCacheHit.Load(), gDNSLookupsResolved.Load(),
		gDNSLookupsFailure.Load(), gDNSResolveSmart.Load(), gDNSResolveFallback.Load(),
	}
	gDNSLookupsLiteral.Store(11)
	gDNSLookupsCacheHit.Store(22)
	gDNSLookupsResolved.Store(33)
	gDNSLookupsFailure.Store(5)
	gDNSResolveSmart.Store(27)
	gDNSResolveFallback.Store(6)
	t.Cleanup(func() {
		gDNSLookupsLiteral.Store(saved[0])
		gDNSLookupsCacheHit.Store(saved[1])
		gDNSLookupsResolved.Store(saved[2])
		gDNSLookupsFailure.Store(saved[3])
		gDNSResolveSmart.Store(saved[4])
		gDNSResolveFallback.Store(saved[5])
	})

	text := renderPrometheusMetrics(time.Now())
	for _, want := range []string{
		"# TYPE socksfilter_dns_lookups_total counter",
		`socksfilter_dns_lookups_total{outcome="literal"} 11`,
		`socksfilter_dns_lookups_total{outcome="cache_hit"} 22`,
		`socksfilter_dns_lookups_total{outcome="resolved"} 33`,
		`socksfilter_dns_lookups_total{outcome="failure"} 5`,
		"# TYPE socksfilter_dns_resolutions_total counter",
		`socksfilter_dns_resolutions_total{source="smart_resolver"} 27`,
		`socksfilter_dns_resolutions_total{source="system_fallback"} 6`,
		"# TYPE socksfilter_dns_cache_entries gauge",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	if !strings.Contains(text, "socksfilter_dns_cache_entries ") {
		t.Errorf("metrics output missing dns_cache_entries sample:\n%s", text)
	}
}

// TestPrometheusMetricsIdleCounters 验证空闲回收 counter 按 transport 标签输出。
func TestPrometheusMetricsIdleCounters(t *testing.T) {
	beforeTCP := gIdleClosedTCP.Load()
	beforeUDP := gIdleClosedUDP.Load()
	gIdleClosedTCP.Store(8)
	gIdleClosedUDP.Store(3)
	t.Cleanup(func() {
		gIdleClosedTCP.Store(beforeTCP)
		gIdleClosedUDP.Store(beforeUDP)
	})

	text := renderPrometheusMetrics(time.Now())
	for _, want := range []string{
		"# TYPE socksfilter_idle_timeout_closed_total counter",
		`socksfilter_idle_timeout_closed_total{transport="tcp"} 8`,
		`socksfilter_idle_timeout_closed_total{transport="udp"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// TestPrometheusMetricsEntryErrors 验证入口错误 counter 按 reason 标签输出。
func TestPrometheusMetricsEntryErrors(t *testing.T) {
	saved := [3]int64{gEntryErrHandshake.Load(), gEntryErrBadRequest.Load(), gEntryErrUnsupportedCmd.Load()}
	gEntryErrHandshake.Store(12)
	gEntryErrBadRequest.Store(7)
	gEntryErrUnsupportedCmd.Store(1)
	t.Cleanup(func() {
		gEntryErrHandshake.Store(saved[0])
		gEntryErrBadRequest.Store(saved[1])
		gEntryErrUnsupportedCmd.Store(saved[2])
	})

	text := renderPrometheusMetrics(time.Now())
	for _, want := range []string{
		"# TYPE socksfilter_entry_errors_total counter",
		`socksfilter_entry_errors_total{reason="handshake"} 12`,
		`socksfilter_entry_errors_total{reason="bad_request"} 7`,
		`socksfilter_entry_errors_total{reason="unsupported_command"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// TestPrometheusMetricsHealthProbes 验证主动健康探测 counter：srv0 写入
// 10 次探测/3 次失败后输出 success=7、failure=3；其余上游输出两个零值样本。
func TestPrometheusMetricsHealthProbes(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv0 := strings.Fields(*servers)[0]
	getUpstreamHealth(srv0).probeAttempts.Store(10)
	getUpstreamHealth(srv0).probeFails.Store(3)

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_upstream_health_probes_total counter") {
		t.Fatal("missing TYPE declaration for socksfilter_upstream_health_probes_total")
	}
	for _, want := range []string{
		fmt.Sprintf(`socksfilter_upstream_health_probes_total{upstream=%q,outcome="success"} 7`, srv0),
		fmt.Sprintf(`socksfilter_upstream_health_probes_total{upstream=%q,outcome="failure"} 3`, srv0),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	for _, srv := range strings.Fields(*servers) {
		if srv == srv0 {
			continue
		}
		for _, outcome := range []string{"success", "failure"} {
			want := fmt.Sprintf(`socksfilter_upstream_health_probes_total{upstream=%q,outcome=%q} 0`, srv, outcome)
			if !strings.Contains(text, want) {
				t.Errorf("metrics output missing zero sample %q", want)
			}
		}
	}
}

// TestRecordProbeLatencyBuckets 验证观测桶边界：恰好等于上界落入该桶（<=），
// 超过最大上界 10s 的观测不进入任何有限桶（渲染时仅计入 +Inf）。
func TestRecordProbeLatencyBuckets(t *testing.T) {
	h := &upstreamHealth{}
	h.recordProbeLatency(5 * time.Millisecond)             // 恰好 0.005s -> 第一个有限桶
	h.recordProbeLatency(10 * time.Second)                 // 恰好最大上界 -> 最后一个有限桶
	h.recordProbeLatency(10*time.Second + time.Nanosecond) // 溢出 -> 仅 +Inf
	if h.probeLatencyBuckets[0].Load() != 1 {
		t.Errorf("first bucket=%d, want 1", h.probeLatencyBuckets[0].Load())
	}
	last := len(probeLatencyUpperBounds) - 1
	if h.probeLatencyBuckets[last].Load() != 1 {
		t.Errorf("last finite bucket=%d, want 1", h.probeLatencyBuckets[last].Load())
	}
	var finite int64
	for i := range h.probeLatencyBuckets {
		finite += h.probeLatencyBuckets[i].Load()
	}
	if finite != 2 {
		t.Errorf("finite bucket observations=%d, want 2", finite)
	}
}

// TestPrometheusMetricsProbeLatency 验证探测延迟 gauge 与直方图：3 次观测
// （0.0001s / 3s / 30s），有限桶按累积口径渲染，30s 只落入 +Inf，
// sum=33.0001s、count 与 +Inf 均等于探测总次数 3。
func TestPrometheusMetricsProbeLatency(t *testing.T) {
	oldServers := *servers
	srv := "127.0.0.1:19999"
	*servers = srv
	resetUpstreamHealth()
	t.Cleanup(func() {
		*servers = oldServers
		resetUpstreamHealth()
	})

	h := getUpstreamHealth(srv)
	h.probeAttempts.Store(3)
	h.recordProbeLatency(100 * time.Microsecond) // 0.0001s -> le=0.005
	h.recordProbeLatency(3 * time.Second)        // 3s -> le=5
	h.recordProbeLatency(30 * time.Second)       // 超过 10s，仅进 +Inf

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_upstream_health_probe_last_duration_seconds gauge") {
		t.Fatal("missing TYPE for last duration gauge")
	}
	if !strings.Contains(text, "# TYPE socksfilter_upstream_health_probe_duration_seconds histogram") {
		t.Fatal("missing TYPE for duration histogram")
	}
	if want := `socksfilter_upstream_health_probe_last_duration_seconds{upstream="127.0.0.1:19999"} 30.000000`; !strings.Contains(text, want) {
		t.Errorf("missing last-duration sample %q", want)
	}
	for _, c := range []struct {
		le string
		v  int64
	}{
		{"0.005", 1}, {"0.01", 1}, {"0.025", 1}, {"0.05", 1}, {"0.1", 1}, {"0.25", 1},
		{"0.5", 1}, {"1", 1}, {"2.5", 1}, {"5", 2}, {"10", 2}, {"+Inf", 3},
	} {
		want := fmt.Sprintf(`socksfilter_upstream_health_probe_duration_seconds_bucket{upstream=%q,le=%q} %d`, srv, c.le, c.v)
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	for _, want := range []string{
		`socksfilter_upstream_health_probe_duration_seconds_sum{upstream="127.0.0.1:19999"} 33.000100`,
		`socksfilter_upstream_health_probe_duration_seconds_count{upstream="127.0.0.1:19999"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// TestPrometheusMetricsHealthTransitions 验证健康状态翻转 counter：srv0
// 写入 2 次摘除/1 次恢复后输出对应样本，其余上游输出两个零值样本。
func TestPrometheusMetricsHealthTransitions(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv0 := strings.Fields(*servers)[0]
	getUpstreamHealth(srv0).markedDead.Store(2)
	getUpstreamHealth(srv0).recovered.Store(1)

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_upstream_health_transitions_total counter") {
		t.Fatal("missing TYPE declaration for socksfilter_upstream_health_transitions_total")
	}
	for _, want := range []string{
		fmt.Sprintf(`socksfilter_upstream_health_transitions_total{upstream=%q,event="marked_dead"} 2`, srv0),
		fmt.Sprintf(`socksfilter_upstream_health_transitions_total{upstream=%q,event="recovered"} 1`, srv0),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	for _, srv := range strings.Fields(*servers) {
		if srv == srv0 {
			continue
		}
		for _, event := range []string{"marked_dead", "recovered"} {
			want := fmt.Sprintf(`socksfilter_upstream_health_transitions_total{upstream=%q,event=%q} 0`, srv, event)
			if !strings.Contains(text, want) {
				t.Errorf("metrics output missing zero sample %q", want)
			}
		}
	}
}

// TestPrometheusMetricsTrafficFailures 验证被动流量失败分阶段 counter：
// srv0 写入 dial=5/handshake=2/request=3/write=1 后输出对应样本，其余上游输出零值。
func TestPrometheusMetricsTrafficFailures(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)

	srv0 := strings.Fields(*servers)[0]
	getUpstreamHealth(srv0).trafficFailsDial.Store(5)
	getUpstreamHealth(srv0).trafficFailsHandshake.Store(2)
	getUpstreamHealth(srv0).trafficFailsRequest.Store(3)
	getUpstreamHealth(srv0).trafficFailsWrite.Store(1)

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_upstream_traffic_failures_total counter") {
		t.Fatal("missing TYPE declaration for socksfilter_upstream_traffic_failures_total")
	}
	for _, want := range []string{
		fmt.Sprintf(`socksfilter_upstream_traffic_failures_total{upstream=%q,stage="dial"} 5`, srv0),
		fmt.Sprintf(`socksfilter_upstream_traffic_failures_total{upstream=%q,stage="handshake"} 2`, srv0),
		fmt.Sprintf(`socksfilter_upstream_traffic_failures_total{upstream=%q,stage="request"} 3`, srv0),
		fmt.Sprintf(`socksfilter_upstream_traffic_failures_total{upstream=%q,stage="write"} 1`, srv0),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	for _, srv := range strings.Fields(*servers) {
		if srv == srv0 {
			continue
		}
		for _, stage := range []string{"dial", "handshake", "request", "write"} {
			want := fmt.Sprintf(`socksfilter_upstream_traffic_failures_total{upstream=%q,stage=%q} 0`, srv, stage)
			if !strings.Contains(text, want) {
				t.Errorf("metrics output missing zero sample %q", want)
			}
		}
	}
}

// TestPrometheusMetricsHealthState 验证三态健康 gauge：每个上游恰好一个
// state 标签值为 1（one-hot），且与二元 up gauge 一致（alive/half_open
// 为 1，dead 为 0）。三态各造一个上游：默认 alive、刚摘除 dead、摘除
// 已超过冷却窗口的 half_open（用固定 deadAt 构造，不改全局冷却）。
func TestPrometheusMetricsHealthState(t *testing.T) {
	resetUpstreamHealth()
	t.Cleanup(resetUpstreamHealth)
	oldServers := *servers
	srvAlive, srvDead, srvHalf := "127.0.0.1:2001", "127.0.0.1:2002", "127.0.0.1:2003"
	*servers = srvAlive + " " + srvDead + " " + srvHalf
	t.Cleanup(func() { *servers = oldServers })

	now := time.Now()
	oldCooldown := gHealthCooldown.Load()
	gHealthCooldown.Store(int64(10 * time.Second))
	t.Cleanup(func() { gHealthCooldown.Store(oldCooldown) })
	getUpstreamHealth(srvAlive) // 默认即 alive
	dh := getUpstreamHealth(srvDead)
	dh.alive.Store(false)
	dh.deadAt.Store(now.UnixNano())
	hh := getUpstreamHealth(srvHalf)
	hh.alive.Store(false)
	hh.deadAt.Store(now.Add(-time.Hour).UnixNano()) // 默认冷却 10s，早已过期 -> half_open

	text := renderPrometheusMetrics(now)
	if !strings.Contains(text, "# TYPE socksfilter_upstream_health_state gauge") {
		t.Fatal("missing TYPE declaration for socksfilter_upstream_health_state")
	}
	wantStates := map[string]string{
		srvAlive: "alive",
		srvDead:  "dead",
		srvHalf:  "half_open",
	}
	wantUp := map[string]int{srvAlive: 1, srvDead: 0, srvHalf: 1}
	for srv, state := range wantStates {
		ones := 0
		for _, st := range upstreamHealthStates {
			line := fmt.Sprintf(`socksfilter_upstream_health_state{upstream=%q,state=%q}`, srv, st)
			if !strings.Contains(text, line+" ") {
				t.Fatalf("missing sample %q", line)
			}
			if strings.Contains(text, line+" 1") {
				ones++
				if st != state {
					t.Errorf("%s reports state=%s as 1, want %s", srv, st, state)
				}
			}
		}
		if ones != 1 {
			t.Errorf("%s one-hot state count=%d, want exactly 1", srv, ones)
		}
		upLine := fmt.Sprintf("socksfilter_upstream_up{upstream=%q} %d", srv, wantUp[srv])
		if !strings.Contains(text, upLine) {
			t.Errorf("missing/ inconsistent up sample %q", upLine)
		}
	}
}

func TestPrometheusMetricsEmptyUpstreams(t *testing.T) {
	oldServers := *servers
	*servers = ""
	t.Cleanup(func() { *servers = oldServers })

	text := renderPrometheusMetrics(time.Now())
	if !strings.Contains(text, "# TYPE socksfilter_upstream_up gauge") {
		t.Errorf("upstream TYPE declarations should still be emitted")
	}
	if strings.Contains(text, "socksfilter_upstream_up{") {
		t.Errorf("no upstream samples expected with empty server list:\n%s", text)
	}
	if !strings.Contains(text, "socksfilter_max_connections 0") {
		t.Errorf("expected max_connections gauge present")
	}
}

func TestPromLabelValueEscape(t *testing.T) {
	got := promLabelValue(`a"b` + "\\" + `c
d`)
	if got != `a\"b\\c\nd` {
		t.Errorf("unexpected escaping: %q", got)
	}
}

// ---- -config JSON 配置文件 ----

// newConfigTestFlagSet 构造与真实 flag 类型分布一致的独立集合，避免污染
// 全局 flag.CommandLine。
func newConfigTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("testconfig", flag.ContinueOnError)
	fs.String("l", ":1080", "")
	fs.String("s", "server1 server2 server3", "")
	fs.Int("dial-timeout", 10, "")
	fs.Int("max-conn", 0, "")
	fs.Bool("version", false, "")
	fs.String("config", "", "")
	return fs
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fail: %v", err)
	}
	return path
}

func TestConfigLoadsStringIntBool(t *testing.T) {
	fs := newConfigTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, `{
		"l": "127.0.0.1:1080",
		"s": "up1:1080 up2:1080",
		"dial-timeout": 7,
		"max-conn": 100,
		"version": true
	}`)
	if err := loadFlagsFromConfig(fs, path); err != nil {
		t.Fatalf("load fail: %v", err)
	}
	if got := fs.Lookup("l").Value.String(); got != "127.0.0.1:1080" {
		t.Errorf("l=%q", got)
	}
	if got := fs.Lookup("s").Value.String(); got != "up1:1080 up2:1080" {
		t.Errorf("s=%q", got)
	}
	if got := fs.Lookup("dial-timeout").Value.String(); got != "7" {
		t.Errorf("dial-timeout=%q", got)
	}
	if got := fs.Lookup("max-conn").Value.String(); got != "100" {
		t.Errorf("max-conn=%q", got)
	}
	if got := fs.Lookup("version").Value.String(); got != "true" {
		t.Errorf("version=%q", got)
	}
}

func TestConfigCLIExplicitWins(t *testing.T) {
	fs := newConfigTestFlagSet()
	if err := fs.Parse([]string{"-dial-timeout", "42", "-s", "cli:1"}); err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, `{
		"dial-timeout": 7,
		"s": "fromfile:2",
		"l": "fromfile:1080"
	}`)
	if err := loadFlagsFromConfig(fs, path); err != nil {
		t.Fatalf("load fail: %v", err)
	}
	if got := fs.Lookup("dial-timeout").Value.String(); got != "42" {
		t.Errorf("explicit int flag overridden: %s", got)
	}
	if got := fs.Lookup("s").Value.String(); got != "cli:1" {
		t.Errorf("explicit string flag overridden: %s", got)
	}
	if got := fs.Lookup("l").Value.String(); got != "fromfile:1080" {
		t.Errorf("non-explicit flag should come from file: %s", got)
	}
}

func TestConfigNumberKeepsIntegerLexeme(t *testing.T) {
	fs := newConfigTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, `{"max-conn": 86400, "dial-timeout": -3}`)
	if err := loadFlagsFromConfig(fs, path); err != nil {
		t.Fatalf("load fail: %v", err)
	}
	if got := fs.Lookup("max-conn").Value.String(); got != "86400" {
		t.Errorf("large integer mangled: %s", got)
	}
	if got := fs.Lookup("dial-timeout").Value.String(); got != "-3" {
		t.Errorf("negative integer mangled: %s", got)
	}
}

func TestConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantSub string
	}{
		{"malformed json", `{"s": }`, "parse config"},
		{"not an object", `["s"]`, "cannot unmarshal"},
		{"unknown flag", `{"nope": 1}`, "unknown flag"},
		{"config inside config", `{"config": "x.json"}`, `cannot be set`},
		{"null value", `{"s": null}`, "null is not"},
		{"array value", `{"s": ["a"]}`, "unsupported value type"},
		{"object value", `{"s": {"a": 1}}`, "unsupported value type"},
		{"wrong value type for int", `{"dial-timeout": "abc"}`, "set -dial-timeout"},
		{"top-level scalar", `"s"`, "cannot unmarshal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newConfigTestFlagSet()
			if err := fs.Parse(nil); err != nil {
				t.Fatal(err)
			}
			path := writeConfigFile(t, tc.content)
			err := loadFlagsFromConfig(fs, path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestConfigFileMissing(t *testing.T) {
	fs := newConfigTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	err := loadFlagsFromConfig(fs, filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "read config") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestConfigEmptyFileIsNoop(t *testing.T) {
	fs := newConfigTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, `{}`)
	if err := loadFlagsFromConfig(fs, path); err != nil {
		t.Fatalf("empty object should be valid, got %v", err)
	}
	if got := fs.Lookup("l").Value.String(); got != ":1080" {
		t.Errorf("defaults changed unexpectedly: l=%s", got)
	}
	if got := fs.Lookup("dial-timeout").Value.String(); got != "10" {
		t.Errorf("defaults changed unexpectedly: dial-timeout=%s", got)
	}
}

func TestConfigStringAcceptedByBoolFlag(t *testing.T) {
	// 字符串 "false" 经 flag 包解析为 false：与命令行 -version=false 行为一致。
	fs := newConfigTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, `{"version": "false"}`)
	if err := loadFlagsFromConfig(fs, path); err != nil {
		t.Fatalf("load fail: %v", err)
	}
	if got := fs.Lookup("version").Value.String(); got != "false" {
		t.Errorf("version=%q", got)
	}
}
