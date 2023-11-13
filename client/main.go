package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"os/signal"
	"syscall"

	"github.com/ccsexyz/kcp-go-raw"
	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/smux"
	"github.com/ccsexyz/utils"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/xtaci/kcp-go"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
)

type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func (c *compStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *compStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *compStream) Close() error {
	return c.conn.Close()
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

var udpBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

func handleTunnelUDPClient(sess *smux.Session, p1 net.Conn, target string) {
	defer p1.Close()

	if len(target) > 256 {
		return
	}

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	err = socks6HandShake(p2, "udprelay", 6666)
	if err != nil {
		return
	}

	buf := udpBufPool.Get().([]byte)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(target)))
	copy(buf[2:], target)

	_, err = p2.Write(buf[:len(target)+2])
	udpBufPool.Put(buf)
	buf = nil
	if err != nil {
		return
	}

	log.Println("udp tunnel opened", target)
	defer log.Println("udp tunnel closed", target)

	tosec := 60
	if strings.HasSuffix(target, ":53") {
		tosec = 5
	}

	utils.PipeUDPOverTCP(p1, p2, &udpBufPool, time.Second*time.Duration(tosec), nil)
}

func handleUDPClient(sess *smux.Session, p1 net.Conn) {
	defer p1.Close()

	buf := udpBufPool.Get().([]byte)
	defer func() {
		if buf != nil {
			udpBufPool.Put(buf)
		}
	}()

	n, err := p1.Read(buf)
	if err != nil {
		return
	}

	if n < 3 {
		return
	}

	addr, data, err := ss.ParseAddr(buf[3:n])
	if err != nil || addr == nil {
		return
	}

	header := make([]byte, n-len(data))
	copy(header, buf)

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	err = socks6HandShake(p2, "udprelay", 6666)
	if err != nil {
		return
	}

	wbuf := udpBufPool.Get().([]byte)
	defer func() {
		if wbuf != nil {
			udpBufPool.Put(wbuf)
		}
	}()

	target := addr.String()
	binary.BigEndian.PutUint16(wbuf, uint16(len(target)))
	off := 2
	off += copy(wbuf[off:], target)
	if len(data) > 0 {
		binary.BigEndian.PutUint16(wbuf[off:], uint16(len(data)))
		off += 2
		off += copy(wbuf[off:], data)
	}

	_, err = p2.Write(wbuf[:off])
	if err != nil {
		return
	}

	log.Println("udp opened", target)
	defer log.Println("udp closed", target)

	udpBufPool.Put(buf)
	udpBufPool.Put(wbuf)
	buf = nil
	wbuf = nil

	tosec := 60
	if strings.HasSuffix(target, ":53") {
		tosec = 5
	}

	utils.PipeUDPOverTCP(p1, p2, &udpBufPool, time.Second*time.Duration(tosec), header)
}

func handleTunnelClient(sess *smux.Session, p1 net.Conn, host string, port int) {
	defer p1.Close()

	if len(host) == 0 || port == 0 {
		return
	}

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	err = socks6HandShake(p2, host, port)
	if err != nil {
		return
	}

	log.Println("tcp tunnel opened", host, port)
	defer log.Println("tcp tunnel closed", host, port)

	pipe(p1, p2)
}

func handleProxyClient(sess *smux.Session, p1 net.Conn, cfg *Config) {
	defer func() {
		if p1 != nil {
			p1.Close()
		}
	}()

	p1 = cfg.proxyAcceptor(p1)
	if p1 == nil {
		return
	}

	ssconn, ok := p1.(ss.Conn)
	if !ok {
		return
	}
	target := ssconn.GetDst().String()

	host, port, err := utils.SplitHostAndPort(target)
	if err != nil {
		return
	}

	var direct bool
	ip := net.ParseIP(host)

	if ip != nil && cfg.chnRouteCtx != nil {
		direct = cfg.chnRouteCtx.testIP(ip)
	} else if cfg.autoProxyCtx != nil {
		direct = !cfg.autoProxyCtx.checkIfProxy(host)
	}

	var p2 net.Conn
	defer func() {
		if p2 != nil {
			p2.Close()
		}
	}()

	if direct {
		p2, err = net.Dial("tcp", target)
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		p2, err = sess.OpenStream()
		if err != nil {
			return
		}
		if len(host) != 0 && port > 0 {
			err = socks6HandShake(p2, host, port)
			if err != nil {
				return
			}
		}
	}

	var directStr string
	if direct {
		directStr = "direct"
	}

	log.Println("stream opened", target, directStr)
	defer log.Println("stream closed", target, directStr)

	pipe(p1, p2)
}

func handleClient(sess *smux.Session, p1 net.Conn) {
	defer p1.Close()

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	log.Println("stream opened")
	defer log.Println("stream closed")

	pipe(p1, p2)
}

func pipe(p1, p2 net.Conn) {
	// start tunnel
	p1die := make(chan struct{})
	go func() { io.Copy(p1, p2); close(p1die) }()

	p2die := make(chan struct{})
	go func() { io.Copy(p2, p1); close(p2die) }()

	// wait for tunnel termination
	select {
	case <-p1die:
	case <-p2die:
	}
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	myApp := cli.NewApp()
	myApp.Name = "kcpraw"
	myApp.Usage = "client(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "vps:29900",
			Usage: "kcp server address",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, chacha20, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "set num of UDP connections to server",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 0,
			Usage: "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 128,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 512,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set dscp(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  40,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "sockbuf",
			Value:  4194304, // socket buffer size in bytes
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "keepalive",
			Value:  10, // nat keepalive interval in seconds
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
		cli.StringFlag{
			Name:  "host",
			Value: "",
			Usage: "hostname for obfuscating (Experimental)",
		},
		cli.BoolFlag{
			Name:  "nohttp",
			Usage: "don't send http request after tcp 3-way handshake",
		},
		cli.IntFlag{
			Name:  "scavengettl",
			Value: 600,
			Usage: "set how long an expired connection can live(in sec), -1 to disable",
		},
		cli.IntFlag{
			Name:  "mulconn",
			Value: 0,
			Usage: "use multiple underlying conns for one kcp connection, default is 0",
		},
		cli.BoolFlag{
			Name:  "udp",
			Usage: "enable udp mode",
		},
		cli.StringFlag{
			Name:  "pprof",
			Usage: "set the listen address for pprof",
		},
		cli.BoolFlag{
			Name:  "nodummy",
			Usage: "don't use dummy socket",
		},
		cli.StringFlag{
			Name:  "proxylist",
			Usage: "set the path of proxy list",
		},
		cli.StringFlag{
			Name:  "chnroute",
			Usage: "set the path of china route",
		},
		cli.BoolFlag{
			Name:  "proxy",
			Usage: "enable default proxy(socks4/socks4a/socks5/http)",
		},
		cli.BoolFlag{
			Name:  "udprelay",
			Usage: "enable socks5 udp relay",
		},
		cli.StringFlag{
			Name:  "tunnels",
			Usage: "provide additional tcp/udp tunnels, eg: udp,:10000,8.8.8.8:53;tcp,:10080,www.google.com:80",
		},
		cli.BoolFlag{
			Name:  "tls",
			Usage: "enable tls-obfs",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.LocalAddr = c.String("localaddr")
		config.RemoteAddr = c.String("remoteaddr")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.Conn = c.Int("conn")
		config.AutoExpire = c.Int("autoexpire")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.NoComp = c.Bool("nocomp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.NoHTTP = c.Bool("nohttp")
		config.Host = c.String("host")
		config.ScavengeTTL = c.Int("scavengettl")
		config.MulConn = c.Int("mulconn")
		config.UDP = c.Bool("udp")
		config.Pprof = c.String("pprof")
		config.NoDummpy = c.Bool("nodummy")
		config.ProxyList = c.String("proxylist")
		config.ChnRoute = c.String("chnroute")
		config.UDPRelay = c.Bool("udprelay")
		config.Proxy = c.Bool("proxy")
		config.TLS = c.Bool("tls")
		tunnels := c.String("tunnels")

		if c.String("c") != "" {
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		log.Println("version:", VERSION)
		addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
		checkError(err)
		listener, err := net.ListenTCP("tcp", addr)
		checkError(err)

		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		case "chacha20":
			block, _ = utils.NewChaCha20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}

		if !config.NoHTTP && len(config.Host) == 0 {
			config.NoHTTP = true
		}

		if len(tunnels) != 0 {
			for _, t := range strings.Split(tunnels, ";") {
				tcs := strings.Split(t, ",")
				if len(tcs) != 3 || len(tcs[1]) == 0 || len(tcs[2]) == 0 {
					continue
				}
				config.Tunnels = append(config.Tunnels, &tunnelConfig{
					Type:       tcs[0],
					LocalAddr:  tcs[1],
					RemoteAddr: tcs[2],
				})
			}
		}

		if len(config.ProxyList) != 0 || len(config.ChnRoute) != 0 || config.UDPRelay {
			config.Proxy = true
		}

		log.Println("listening on:", listener.Addr())
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("remote address:", config.RemoteAddr)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("conn:", config.Conn)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("scavengettl:", config.ScavengeTTL)
		log.Println("mulconn:", config.MulConn)
		log.Println("udp mode:", config.UDP)
		log.Println("pprof listen at:", config.Pprof)
		log.Println("dummpy:", !config.NoDummpy)
		log.Println("nohttp:", config.NoHTTP)
		log.Println("httphost:", config.Host)
		log.Println("proxy:", config.Proxy)
		log.Println("proxylist:", config.ProxyList)
		log.Println("chnroute:", config.ChnRoute)
		log.Println("udprelay:", config.UDPRelay)

		if len(config.Pprof) != 0 {
			if utils.PprofEnabled() {
				log.Println("run pprof http server at", config.Pprof)
				go func() {
					utils.RunProfileHTTPServer(config.Pprof)
				}()
			} else {
				log.Println("set pprof but pprof isn't compiled")
			}
		}

		args := make(map[string]interface{})

		if config.UDPRelay {
			args["localaddr"] = config.LocalAddr
			args["udprelay"] = true
		}

		if len(config.ProxyList) != 0 {
			config.autoProxyCtx = newAutoProxy()
			config.autoProxyCtx.loadPorxyList(config.ProxyList)
		}

		if len(config.ChnRoute) != 0 {
			config.chnRouteCtx = new(chnRouteList)
			err := config.chnRouteCtx.load(config.ChnRoute)
			if err != nil {
				log.Println(err)
				config.chnRouteCtx = nil
			}
		}

		if config.Proxy {
			config.proxyAcceptor = ss.GetSocksAcceptor(args)
		}

		kcpraw.SetNoHTTP(config.NoHTTP)
		kcpraw.SetTLS(config.TLS)
		kcpraw.SetHost(config.Host)
		kcpraw.SetDSCP(config.DSCP)
		kcpraw.SetIgnRST(true)
		kcpraw.SetDummy(!config.NoDummpy)

		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = config.SockBuf
		smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

		createConn := func() (*smux.Session, error) {
			kcpconn, err := kcpraw.DialWithOptions(config.RemoteAddr, block, config.DataShard, config.ParityShard, config.Key, config.MulConn, config.UDP)
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			kcpconn.SetStreamMode(true)
			kcpconn.SetWriteDelay(true)
			kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
			kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)

			mss := kcpraw.GetMSSByAddr(kcpconn.LocalAddr(), kcpconn.RemoteAddr())
			if mss > 0 && mss < config.MTU {
				kcpconn.SetMtu(mss)
			} else {
				kcpconn.SetMtu(config.MTU)
			}

			kcpconn.SetACKNoDelay(config.AckNodelay)

			// stream multiplex
			var session *smux.Session
			if config.NoComp {
				session, err = smux.Client(kcpconn, smuxConfig)
			} else {
				session, err = smux.Client(newCompStream(kcpconn), smuxConfig)
			}
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
			return session, nil
		}

		// wait until a connection is ready
		waitConn := func() *smux.Session {
			for {
				if session, err := createConn(); err == nil {
					return session
				} else {
					time.Sleep(time.Second)
				}
			}
		}

		type muxSessInfo struct {
			session *smux.Session
			ttl     time.Time
		}
		var mmuxes [][]muxSessInfo

		sigch := make(chan os.Signal, 2)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigch
			for _, muxes := range mmuxes {
				for _, m := range muxes {
					m.session.Close()
				}
			}
			os.Exit(1)
		}()

		go snmpLogger(config.SnmpLog, config.SnmpPeriod)

		newSessionDailer := func() func() *smux.Session {
			numconn := uint16(config.Conn)
			muxes := make([]muxSessInfo, numconn)
			mmuxes = append(mmuxes, muxes)

			for k := range muxes {
				sess, err := createConn()
				checkError(err)
				muxes[k].session = sess
				muxes[k].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			}

			chScavenger := make(chan *smux.Session, 128)
			go scavenger(chScavenger, config.ScavengeTTL)
			rr := uint16(0)
			var rrLock sync.Mutex
			return func() *smux.Session {
				rrLock.Lock()
				defer rrLock.Unlock()

				idx := rr % numconn

				// do auto expiration && reconnection
				if muxes[idx].session.IsClosed() || (config.AutoExpire > 0 && time.Now().After(muxes[idx].ttl)) {
					chScavenger <- muxes[idx].session
					muxes[idx].session = waitConn()
					muxes[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
				}
				rr++

				return muxes[idx].session
			}
		}

		dialSessionForTCP := newSessionDailer()
		var dialSessionForUDPImp func() *smux.Session
		var udpDialerOnce sync.Once
		dialSessionForUDP := func() *smux.Session {
			udpDialerOnce.Do(func() { dialSessionForUDPImp = newSessionDailer() })
			return dialSessionForUDPImp()
		}

		if config.UDPRelay {
			udpListener, err := utils.ListenSubUDP("udp", config.LocalAddr)
			if err != nil {
				log.Fatalln(err)
			}
			go func() {
				defer udpListener.Close()
				for {
					p1, err := udpListener.Accept()
					if err != nil {
						log.Fatalln(err)
					}
					session := dialSessionForUDP()
					if session == nil {
						p1.Close()
						continue
					}
					go handleUDPClient(session, p1)
				}
			}()
		}
		runUDPTunnelListener := func(ctx *tunnelConfig) {
			if len(ctx.LocalAddr) == 0 || len(ctx.RemoteAddr) == 0 || len(ctx.RemoteAddr) > 256 {
				return
			}
			log.Println("run udp tunnel:", ctx.LocalAddr, "->", ctx.RemoteAddr)
			udpListener, err := utils.ListenSubUDP("udp", ctx.LocalAddr)
			if err != nil {
				log.Fatalln(err)
			}
			defer udpListener.Close()
			for {
				p1, err := udpListener.Accept()
				if err != nil {
					log.Fatalln(err)
				}
				session := dialSessionForUDP()
				if session == nil {
					p1.Close()
					continue
				}
				go handleTunnelUDPClient(session, p1, ctx.RemoteAddr)
			}
		}
		runTCPTunnelListener := func(ctx *tunnelConfig) {
			if config.proxyAcceptor == nil {
				return
			}
			log.Println("run tcp tunnel:", ctx.LocalAddr, "->", ctx.RemoteAddr)
			tcpAddr, err := net.ResolveTCPAddr("tcp", ctx.LocalAddr)
			if err != nil {
				log.Fatalln(err)
			}
			tcpTunnelListener, err := net.ListenTCP("tcp", tcpAddr)
			checkError(err)
			defer tcpTunnelListener.Close()
			host, port, err := utils.SplitHostAndPort(ctx.RemoteAddr)
			if err != nil {
				log.Fatalln(err)
			}
			for {
				p1, err := tcpTunnelListener.Accept()
				if err != nil {
					log.Fatalln(err)
				}
				go func(conn net.Conn) {
					session := dialSessionForTCP()
					if session == nil {
						conn.Close()
						return
					}
					handleTunnelClient(session, p1, host, port)
				}(p1)
			}
		}
		for _, tunnel := range config.Tunnels {
			if tunnel.Type == "udp" {
				if config.UDPRelay != true {
					continue
				}
				go runUDPTunnelListener(tunnel)
			} else {
				go runTCPTunnelListener(tunnel)
			}
		}
		for {
			p1, err := listener.AcceptTCP()
			if err != nil {
				log.Fatalln(err)
			}
			checkError(err)
			go func(conn net.Conn) {
				session := dialSessionForTCP()
				if session == nil {
					conn.Close()
					return
				}

				target, _ := redir.GetOrigDst(conn)
				if (len(target) != 0 && target == conn.LocalAddr().String()) ||
					config.proxyAcceptor == nil {
					target = ""
				}

				if len(target) > 0 {
					host, port, err := utils.SplitHostAndPort(target)
					if err != nil {
						conn.Close()
						return
					}
					handleTunnelClient(session, conn, host, port)
				} else if config.proxyAcceptor != nil {
					handleProxyClient(session, conn, &config)
				} else {
					handleClient(session, conn)
				}
			}(p1)
		}
	}
	myApp.Run(os.Args)
}

type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

func scavenger(ch chan *smux.Session, ttl int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		select {
		case sess := <-ch:
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
			log.Println("session marked as expired")
		case <-ticker.C:
			var newList []scavengeSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					log.Println("session normally closed")
					s.session.Close()
				} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl)*time.Second {
					log.Println("session reached scavenge ttl")
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}

func snmpLogger(path string, interval int) {
	if path == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f, err := os.OpenFile(time.Now().Format(path), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				log.Println(err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					log.Println(err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				log.Println(err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}
