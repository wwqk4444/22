package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func socks6HandShake(conn net.Conn, host string, port int) error {
	if len(host) > 255 {
		return fmt.Errorf("host length can't be greater than 255")
	}
	buf := make([]byte, 512)
	buf[0] = 6
	buf[1] = 1
	n := ss.PutHeader(buf[2:], host, port)
	_, err := conn.Write(buf[:2+n])
	if err != nil {
		return err
	}
	return nil
}

func socks4aHandShake(conn net.Conn, host string, port int) error {
	buf := make([]byte, 512)
	buf[0] = 0x4
	buf[1] = 0x1
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	buf[7] = 127
	buf[8] = 'h'
	buf[9] = 'a'
	buf[10] = 0
	copy(buf[11:], utils.StringToSlice(host))
	buf[11+len(host)] = 0
	_, err := conn.Write(buf[:len(host)+12])
	if err != nil {
		return err
	}
	n, err := conn.Read(buf[:8])
	if err != nil {
		return err
	}
	if n != 8 {
		return io.ErrShortBuffer
	}
	return nil
}

func newAutoProxy() *autoProxy {
	return &autoProxy{
		byPassDmRoot: utils.NewDomainRoot(),
		proxyDmRoot:  utils.NewDomainRoot(),
	}
}

type autoProxy struct {
	byPassDmRoot *utils.DomainRoot
	proxyDmRoot  *utils.DomainRoot
	lock         sync.RWMutex
}

func (ap *autoProxy) loadByPassList(bypassList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(bypassList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.byPassDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) loadPorxyList(proxyList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(proxyList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.proxyDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) getByPassHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.byPassDmRoot.Get()
	return hosts
}

func (ap *autoProxy) getProxyHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.proxyDmRoot.Get()
	return hosts
}

func (ap *autoProxy) markHostNeedProxy(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.proxyDmRoot.Put(host)
}

func (ap *autoProxy) markHostByPass(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.byPassDmRoot.Put(host)
}

func (ap *autoProxy) checkIfProxy(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.proxyDmRoot.Test(host)
}

func (ap *autoProxy) checkIfByPass(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.byPassDmRoot.Test(host)
}

type chnRouteList struct {
	tree *utils.IPTree
	lock sync.RWMutex
}

func (route *chnRouteList) load(path string) (err error) {
	route.lock.Lock()
	defer route.lock.Unlock()
	if route.tree == nil {
		route.tree = utils.NewIPTree()
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		route.tree.Insert(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (route *chnRouteList) testIP(ip net.IP) bool {
	route.lock.RLock()
	defer route.lock.RUnlock()
	return route.tree.TestIP(ip)
}
