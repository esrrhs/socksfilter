package main

import (
	"flag"
	"fmt"
	"github.com/esrrhs/go-engine/src/common"
	"github.com/esrrhs/go-engine/src/geoip"
	"github.com/esrrhs/go-engine/src/loggo"
	"github.com/esrrhs/go-engine/src/network"
	"io"
	"math/rand"
	"net"
	"strings"
)

var listen = flag.String("l", ":1080", "listen addr")
var servers = flag.String("s", "server1 server2 server3", "server addr")
var sel = flag.String("select", "robin", "select server robin/rand/hash_by_dst_ip/hash_by_src_ip/hash_all")
var skip = flag.String("skip", "CN", "skip country")
var filename = flag.String("file", "GeoLite2-Country.mmdb", "ip file")
var loglevel = flag.String("loglevel", "info", "log level")
var nolog = flag.Int("nolog", 0, "write log file")
var noprint = flag.Int("noprint", 0, "print stdout")

func main() {

	flag.Parse()

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
	loggo.Info("start...")

	err := geoip.Load(*filename)
	if err != nil {
		loggo.Error("Load Sock5 ip file ERROR: %s", err.Error())
		return
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
	loggo.Info("listen ok %s", tcpaddr.String())

	for {
		conn, err := tcplistenConn.AcceptTCP()
		if err != nil {
			loggo.Info("Error accept tcp %s", err)
			continue
		}

		go process(conn)
	}
}

func need_proxy(addr string) bool {

	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return false
	}

	ret, err := geoip.GetCountryIsoCode(taddr.IP.String())
	if err != nil {
		return false
	}
	if len(ret) <= 0 {
		return false
	}

	return ret != *skip
}

func process(conn *net.TCPConn) {

	defer common.CrashLog()

	var err error = nil
	if err = network.Sock5HandshakeBy(conn, "", ""); err != nil {
		loggo.Error("process socks handshake: %s", err)
		conn.Close()
		return
	}
	_, targetAddr, err := network.Sock5GetRequest(conn)
	if err != nil {
		loggo.Error("process error getting request: %s", err)
		conn.Close()
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		loggo.Error("process send connection confirmation: %s", err)
		conn.Close()
		return
	}

	tcpaddrTarget, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		loggo.Info("process tcp ResolveTCPAddr fail: %s %s", targetAddr, err.Error())
		return
	}

	loggo.Info("process accept new sock5 conn: %s", targetAddr)

	if need_proxy(targetAddr) {
		process_proxy(conn, targetAddr, tcpaddrTarget)
	} else {
		process_direct(conn, targetAddr, tcpaddrTarget)
	}
}

func process_proxy_server(conn *net.TCPConn, targetAddr string, tcpaddrTarget *net.TCPAddr, server string) bool {

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

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	err = network.Sock5Handshake(proxyconn, 0, "", "")
	if err != nil {
		loggo.Info("process_proxy_server Sock5Handshake fail: %s %s", targetAddr, err.Error())
		return false
	}

	err = network.Sock5SetRequest(proxyconn, tcpaddrTarget.IP.String(), tcpaddrTarget.Port, 0)
	if err != nil {
		loggo.Info("process_proxy_server Sock5SetRequest fail: %s %s", targetAddr, err.Error())
		return false
	}

	loggo.Info("client accept new proxy local tcp %s %s %s", server, tcpsrcaddr.String(), targetAddr)

	errCh := make(chan error, 2)
	go proxy(conn, proxyconn, conn.RemoteAddr().String(), proxyconn.RemoteAddr().String(), errCh)
	go proxy(proxyconn, conn, proxyconn.RemoteAddr().String(), conn.RemoteAddr().String(), errCh)

	for i := 0; i < 2; i++ {
		<-errCh
	}

	conn.Close()
	proxyconn.Close()

	return true
}

func process_proxy(conn *net.TCPConn, targetAddr string, tcpaddrTarget *net.TCPAddr) {

	ss := strings.Fields(*servers)
	if len(ss) <= 0 {
		loggo.Error("process_proxy no servers fail: %s", targetAddr)
		return
	}
	if *sel == "robin" {
		for _, server := range ss {
			if process_proxy_server(conn, targetAddr, tcpaddrTarget, server) {
				return
			}
		}
	} else if *sel == "rand" {
		rand.Shuffle(len(ss), func(i, j int) {
			ss[i], ss[j] = ss[j], ss[i]
		})
		for _, server := range ss {
			if process_proxy_server(conn, targetAddr, tcpaddrTarget, server) {
				return
			}
		}
	} else if *sel == "hash_by_dst_ip" {
		hash := int(common.HashString(tcpaddrTarget.IP.String()))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, tcpaddrTarget, server) {
				return
			}
		}
	} else if *sel == "hash_by_src_ip" {
		hash := int(common.HashString(conn.RemoteAddr().(*net.TCPAddr).IP.String()))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, tcpaddrTarget, server) {
				return
			}
		}
	} else if *sel == "hash_all" {
		hash := int(common.HashString(conn.RemoteAddr().String() + "-" + tcpaddrTarget.String()))
		for i := 0; i < len(ss); i++ {
			server := ss[(hash+i)%len(ss)]
			if process_proxy_server(conn, targetAddr, tcpaddrTarget, server) {
				return
			}
		}
	} else {
		loggo.Error("process_proxy select type error: %s", *sel)
	}
	loggo.Info("process_proxy no valid servers fail: %s", *servers)
}

func process_direct(conn *net.TCPConn, targetAddr string, tcpaddrTarget *net.TCPAddr) {

	targetconn, err := net.DialTCP("tcp", nil, tcpaddrTarget)
	if err != nil {
		loggo.Info("process_direct tcp DialTCP fail: %s %s", targetAddr, err.Error())
		return
	}

	tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

	loggo.Info("process_direct client accept new direct local tcp %s %s", tcpsrcaddr.String(), targetAddr)

	errCh := make(chan error, 2)
	go proxy(conn, targetconn, conn.RemoteAddr().String(), targetconn.RemoteAddr().String(), errCh)
	go proxy(targetconn, conn, targetconn.RemoteAddr().String(), conn.RemoteAddr().String(), errCh)

	for i := 0; i < 2; i++ {
		<-errCh
	}

	conn.Close()
	targetconn.Close()
}

func proxy(destination io.Writer, source io.Reader, dst string, src string, errCh chan error) {
	loggo.Info("transfer client begin transfer from %s -> %s", src, dst)
	n, err := io.Copy(destination, source)
	errCh <- err
	loggo.Info("transfer client end transfer from %s -> %s %v %v", src, dst, n, err)
}
