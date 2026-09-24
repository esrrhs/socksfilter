package main

import (
	"context"
	"net"
	"strings"
	"sync"
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
