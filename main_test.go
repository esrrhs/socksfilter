package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/esrrhs/gohome/common"
)

func Test0001(t *testing.T) {
	host, _, _ := net.SplitHostPort("123.34.22.41:234")
	fmt.Println(host)
	fmt.Println(common.IsValidIP(host))
	host, _, _ = net.SplitHostPort("pss.bdstatic.com:443")
	fmt.Println(host)
	fmt.Println(common.IsValidIP(host))
}

func Test002(t *testing.T) {
	begin := time.Now()
	taddr, err := common.ResolveDomainToIP("www.baidu.com")
	if err != nil {
		fmt.Println("get_ip error: ", err)
		return
	}
	fmt.Println("ResolveDomainToIP: ", taddr, time.Now().Sub(begin))
	begin = time.Now()
	taddr, err = common.ResolveDomainToIP("www.google.com")
	if err != nil {
		fmt.Println("get_ip error: ", err)
		return
	}
	fmt.Println("ResolveDomainToIP: ", taddr, time.Now().Sub(begin))
	begin = time.Now()
	taddr, err = common.ResolveDomainToIP("www.qq.com")
	if err != nil {
		fmt.Println("get_ip error: ", err)
		return
	}
	fmt.Println("ResolveDomainToIP: ", taddr, time.Now().Sub(begin))
	begin = time.Now()
	taddr, err = common.ResolveDomainToIP("www.taobao.com")
	if err != nil {
		fmt.Println("get_ip error: ", err)
		return
	}
	fmt.Println("ResolveDomainToIP: ", taddr, time.Now().Sub(begin))
}

func Test003(t *testing.T) {
	init_env()
	fmt.Println("need proxy baidu", need_proxy("www.baidu.com:443"))
	fmt.Println("need proxy google", need_proxy("www.google.com:443"))
	fmt.Println("need proxy ggpht", need_proxy("yt3.ggpht.com:443"))
	fmt.Println("need proxy ggpht", need_proxy("yt3.ggpht.com:443"))
}
