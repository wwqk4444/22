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

	kcpraw "github.com/ccsexyz/kcp-go-raw"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/smux"
	"github.com/ccsexyz/utils"
	"github.com/golang/snappy"
	"github.com/urfave/cli"
	kcp "github.com/xtaci/kcp-go"
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

// handle multiplex-ed connection
func handleMux(conn io.ReadWriteCloser, config *Config) {
	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = config.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer mux.Close()
	args := make(map[string]interface{})
	var acceptor ss.Acceptor
	if config.DefaultProxy {
		acceptor = ss.GetSocksAcceptor(args)
	} else if config.ShadowProxy {
		args["method"] = "multi"
		args["password"] = config.Key
		acceptor = ss.GetShadowAcceptor(args)
	}
	for {
		p1, err := mux.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}
		go func(conn1 net.Conn) {
			target := config.Target
			if acceptor != nil {
				conn1 = acceptor(conn1)
				if conn1 == nil {
					return
				}
				ssconn, ok := conn1.(ss.Conn)
				if !ok {
					conn1.Close()
					return
				}
				target = ssconn.GetDst().String()
			}
			if target == "udprelay:6666" {
				go handleUDPClient(conn1)
				return
			}
			conn2, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				conn1.Close()
				log.Println(err)
				return
			}
			var suffix string
			if target != config.Target {
				suffix = " (" + target + ")"
			}
			go handleClient(conn1, conn2, suffix)
		}(p1)
	}
}

var udpBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

func handleUDPClient(p1 net.Conn) {
	defer p1.Close()

	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	_, err := io.ReadFull(p1, buf[:2])
	if err != nil {
		return
	}
	sz := int(binary.BigEndian.Uint16(buf[:2]))
	if sz > len(buf) {
		return
	}
	_, err = io.ReadFull(p1, buf[:sz])
	if err != nil {
		return
	}
	target := string(buf[:sz])

	p2, err := net.Dial("udp", target)
	if err != nil {
		log.Println(err)
		return
	}
	defer p2.Close()

	log.Println("udp opened", "("+target+")")
	defer log.Println("udp closed", "("+target+")")

	tosec := 60
	if strings.HasSuffix(target, ":53") {
		tosec = 5
	}

	utils.PipeUDPOverTCP(p2, p1, &udpBufPool, time.Second*time.Duration(tosec), nil)
}

func handleClient(p1, p2 io.ReadWriteCloser, suffix string) {
	log.Println("stream opened", suffix)
	defer log.Println("stream closed", suffix)
	defer p1.Close()
	defer p2.Close()

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
	myApp.Usage = "server(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "listen,l",
			Value: ":29900",
			Usage: "kcp server listen address",
		},
		cli.StringFlag{
			Name:  "target, t",
			Value: "127.0.0.1:12948",
			Usage: "target server address",
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
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 1024,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 1024,
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
			Name:  "usemul",
			Usage: "use multiple underlying conns for one kcp connection",
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
		cli.BoolFlag{
			Name:  "udp",
			Usage: "enable udp mode",
		},
		cli.StringFlag{
			Name:  "pprof",
			Usage: "set the listen address for pprof",
		},
		cli.BoolFlag{
			Name:  "proxy",
			Usage: "enable default proxy(socks4/socks4a/socks5/http)",
		},
		cli.BoolFlag{
			Name:  "ssproxy",
			Usage: "enable shadowsocks proxy",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.Listen = c.String("listen")
		config.Target = c.String("target")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
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
		config.UseMul = c.Bool("usemul")
		config.UDP = c.Bool("udp")
		config.Pprof = c.String("pprof")
		config.DefaultProxy = c.Bool("proxy")
		config.ShadowProxy = c.Bool("ssproxy")

		if c.String("c") != "" {
			//Now only support json config file
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

		kcpraw.SetNoHTTP(false)
		kcpraw.SetMixed(true)
		kcpraw.SetDSCP(config.DSCP)
		kcpraw.SetIgnRST(true)

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

		lis, err := kcpraw.ListenWithOptions(config.Listen, block, config.DataShard, config.ParityShard, config.Key, config.UseMul, config.UDP)
		checkError(err)
		log.Println("listening on:", lis.Addr())
		log.Println("target:", config.Target)
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("usemul:", config.UseMul)
		log.Println("udp mode:", config.UDP)
		log.Println("pprof listen at:", config.Pprof)
		log.Println("default proxy:", config.DefaultProxy)
		log.Println("shadowsocks proxy:", config.ShadowProxy)

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

		sigch := make(chan os.Signal, 2)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigch
			lis.Close()
			os.Exit(1)
		}()

		go snmpLogger(config.SnmpLog, config.SnmpPeriod)
		for {
			if conn, err := lis.AcceptKCP(); err == nil {
				log.Println("remote address:", conn.RemoteAddr())
				conn.SetStreamMode(true)
				conn.SetWriteDelay(true)
				conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
				var mss int
				rawlis := kcpraw.GetListenerByAddr(lis.Addr())
				if rawlis != nil {
					mss = rawlis.GetMSSByAddr(conn.RemoteAddr())
				}
				if mss > 0 && mss < config.MTU {
					conn.SetMtu(mss)
				} else {
					conn.SetMtu(config.MTU)
				}
				conn.SetWindowSize(config.SndWnd, config.RcvWnd)
				conn.SetACKNoDelay(config.AckNodelay)

				if config.NoComp {
					go handleMux(conn, &config)
				} else {
					go handleMux(newCompStream(conn), &config)
				}
			} else {
				log.Printf("%+v", err)
			}
		}
	}
	myApp.Run(os.Args)
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
