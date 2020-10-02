package main

import (
	"flag"
	"github.com/esrrhs/go-engine/src/common"
	"github.com/esrrhs/go-engine/src/geoip"
	"github.com/esrrhs/go-engine/src/loggo"
	"github.com/esrrhs/go-engine/src/network"
	"io"
	"net"
	"strings"
)

var listen = flag.String("l", ":1080", "listen addr")
var servers = flag.String("s", "server1,server2,server3", "server addr")
var skip = flag.String("skip", "CN", "skip country")
var filename = flag.String("file", "GeoLite2-Country.mmdb", "ip file")
var loglevel = flag.String("loglevel", "info", "log level")
var nolog = flag.Int("nolog", 0, "write log file")
var noprint = flag.Int("noprint", 0, "print stdout")

func main() {

	flag.Parse()

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

func process_proxy(conn *net.TCPConn, targetAddr string, tcpaddrTarget *net.TCPAddr) {

	for _, server := range strings.Split(*servers, ",") {

		tcpaddrProxy, err := net.ResolveTCPAddr("tcp", server)
		if err != nil {
			loggo.Info("process_proxy tcp ResolveTCPAddr fail: %s %s", server, err.Error())
			continue
		}

		proxyconn, err := net.DialTCP("tcp", nil, tcpaddrProxy)
		if err != nil {
			loggo.Info("process_proxy tcp DialTCP fail: %s %s", targetAddr, err.Error())
			continue
		}

		tcpsrcaddr := conn.RemoteAddr().(*net.TCPAddr)

		err = network.Sock5Handshake(proxyconn, 1000, "", "")
		if err != nil {
			loggo.Info("process_proxy Sock5Handshake fail: %s %s", targetAddr, err.Error())
			continue
		}

		err = network.Sock5SetRequest(proxyconn, tcpaddrTarget.IP.String(), tcpaddrTarget.Port, 1000)
		if err != nil {
			loggo.Info("process_proxy Sock5SetRequest fail: %s %s", targetAddr, err.Error())
			continue
		}

		loggo.Info("client accept new proxy local tcp %s %s", tcpsrcaddr.String(), targetAddr)

		go transfer(conn, proxyconn, conn.RemoteAddr().String(), proxyconn.RemoteAddr().String())
		go transfer(proxyconn, conn, proxyconn.RemoteAddr().String(), conn.RemoteAddr().String())

		return
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

	go transfer(conn, targetconn, conn.RemoteAddr().String(), targetconn.RemoteAddr().String())
	go transfer(targetconn, conn, targetconn.RemoteAddr().String(), conn.RemoteAddr().String())
}

func transfer(destination io.WriteCloser, source io.ReadCloser, dst string, src string) {

	defer common.CrashLog()

	defer destination.Close()
	defer source.Close()
	loggo.Info("transfer client begin transfer from %s -> %s", src, dst)
	io.Copy(destination, source)
	loggo.Info("transfer client end transfer from %s -> %s", src, dst)
}
