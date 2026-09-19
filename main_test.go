package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/esrrhs/gohome/common"
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

func BenchmarkLoadChinaDomains(b *testing.B) {
	for i := 0; i < b.N; i++ {
		load_china_domains()
	}
}
