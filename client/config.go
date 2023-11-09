package main

import (
	"encoding/json"
	"os"

	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// Config for client
type Config struct {
	LocalAddr    string `json:"localaddr"`
	RemoteAddr   string `json:"remoteaddr"`
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	Conn         int    `json:"conn"`
	AutoExpire   int    `json:"autoexpire"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	Log          string `json:"log"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Obfs         string `json:"obfs"`
	Host         string `json:"host"`
	ScavengeTTL  int    `json:"scavengettl"`
	MulConn      int    `json:"mulconn"`
	UDP          bool   `json:"udp"`
	Pprof        string `json:"pprof"`
	NoDummpy     bool   `json:"nodummy"`
	ProxyList    string `json:"proxylist"`
	ChnRoute     string `json:"chnroute"`
	UDPRelay     bool   `json:"udprelay"`
	Proxy        bool   `json:"proxy"`

	Tunnels []*tunnelConfig `json:"tunnels"`

	proxyAcceptor ss.Acceptor
	autoProxyCtx  *autoProxy
	chnRouteCtx   *chnRouteList
}

type tunnelConfig struct {
	Type       string `json:"type"` // tcp or udp
	LocalAddr  string `json:"localaddr"`
	RemoteAddr string `json:"remoteaddr"`
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}
