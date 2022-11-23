//go:build !noyggdrasil
// +build !noyggdrasil

/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2022 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package yggdrasil

import (
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	iwt "github.com/Arceliar/ironwood/types"
	gologme "github.com/gologme/log"
	yaddr "github.com/yggdrasil-network/yggdrasil-go/src/address"
	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
	ymcast "github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"golang.org/x/crypto/ed25519"
)

const DefaultPort = 5400

// Copy-pasted from yggdrasil-go/src/ipv6rwc/ipv6rwc.go,
// because they are non-exportable.
const (
	typeKeyDummy = iota
	typeKeyLookup
	typeKeyResponse
)

var (
	glog *gologme.Logger

	stacks  map[string]*TCPIPEndpoint
	stacksM sync.Mutex
)

func init() {
	glog = gologme.New(log.Writer(), "yggdrasil: ", gologme.Lmsgprefix)
	glog.EnableLevel("warn")
	glog.EnableLevel("error")
	glog.EnableLevel("info")
	stacks = make(map[string]*TCPIPEndpoint)
}

func ycoreStart(cfg *ycfg.NodeConfig, port int, mcasts []string) (*ycore.Core, error) {
	var err error
	for _, mcast := range mcasts {
		cols := strings.SplitN(mcast, ":", 2)
		mport := 0
		if len(cols) == 2 {
			mcast = cols[0]
			mport, err = strconv.Atoi(cols[1])
			if err != nil {
				return nil, err
			}
		}
		cfg.MulticastInterfaces = append(
			cfg.MulticastInterfaces, ycfg.MulticastInterfaceConfig{
				Regex:  mcast,
				Beacon: true,
				Listen: true,
				Port:   uint16(mport),
			},
		)
	}

	sk, err := hex.DecodeString(cfg.PrivateKey)
	if err != nil {
		panic(err)
	}
	options := []ycore.SetupOption{
		ycore.NodeInfo(cfg.NodeInfo),
		ycore.NodeInfoPrivacy(cfg.NodeInfoPrivacy),
	}
	for _, addr := range cfg.Listen {
		options = append(options, ycore.ListenAddress(addr))
	}
	for _, peer := range cfg.Peers {
		options = append(options, ycore.Peer{URI: peer})
	}
	for intf, peers := range cfg.InterfacePeers {
		for _, peer := range peers {
			options = append(options, ycore.Peer{URI: peer, SourceInterface: intf})
		}
	}
	for _, allowed := range cfg.AllowedPublicKeys {
		k, err := hex.DecodeString(allowed)
		if err != nil {
			panic(err)
		}
		options = append(options, ycore.AllowedPublicKey(k[:]))
	}

	core, err := ycore.New(sk[:], glog, options...)
	if err != nil {
		return nil, err
	}
	if len(mcasts) > 0 {

		options := []ymcast.SetupOption{}
		for _, intf := range cfg.MulticastInterfaces {
			options = append(options, ymcast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
			})
		}
		if _, err = ymcast.New(core, glog, options...); err != nil {
			core.Stop()
			return nil, err
		}
	}
	glog.Infoln("Public key:", hex.EncodeToString(core.GetSelf().Key))
	glog.Infof("NNCP TCP: [%s]:%d", core.Address().String(), port)
	glog.Infoln("MTU:", core.MTU())
	return core, nil
}

func NewConn(aliases map[string]string, in string) (net.Conn, error) {
	// yggdrasilc://PUB[:PORT]?prv=PRV[&peer=PEER][&mcast=REGEX[:PORT]]
	u, err := url.Parse(in)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "yggdrasilc" {
		return nil, errors.New("expected yggdrasilc:// scheme")
	}

	pubHex := u.Hostname()
	if v, ok := aliases[pubHex]; ok {
		pubHex = v
	}
	pubRaw, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}

	port := DefaultPort
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
	}

	values := u.Query()
	if len(values["prv"]) == 0 {
		return nil, errors.New("yggdrasilc:// misses prv field")
	}
	prvHex := values["prv"][0]
	if v, ok := aliases[prvHex]; ok {
		prvHex = v
	}
	prvRaw, err := hex.DecodeString(prvHex)
	if err != nil {
		return nil, err
	}
	if len(prvRaw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	var peers []string
	for _, peer := range values["peer"] {
		if v, ok := aliases[peer]; ok {
			peer = v
		}
		peers = append(peers, peer)
	}
	var mcasts []string
	for _, mcast := range values["mcast"] {
		if v, ok := aliases[mcast]; ok {
			mcast = v
		}
		mcasts = append(mcasts, mcast)
	}

	addrOur := yaddr.AddrForKey(ed25519.PublicKey(
		prvRaw[len(prvRaw)-ed25519.PublicKeySize:],
	))
	ipOur := net.IP(addrOur[:])
	addrTheir := yaddr.AddrForKey(ed25519.PublicKey(pubRaw))
	ipTheir := net.IP(addrTheir[:])
	var ip yaddr.Address
	copy(ip[:], addrTheir[:])

	stacksM.Lock()
	defer stacksM.Unlock()
	e, ok := stacks[prvHex]
	if ok {
		e.ipToAddr[ip] = iwt.Addr(pubRaw)
		return e.DialTCP(&net.TCPAddr{IP: ipTheir, Port: port})
	}
	cfg := ycfg.NodeConfig{
		PrivateKey:      prvHex,
		Peers:           peers,
		NodeInfo:        map[string]interface{}{"name": "NNCP"},
		NodeInfoPrivacy: true,
	}
	core, err := ycoreStart(&cfg, port, mcasts)
	if err != nil {
		return nil, err
	}
	e, err = NewTCPIPEndpoint(core, ipOur, uint32(core.MTU()))
	if err != nil {
		return nil, err
	}
	e.ipToAddr[ip] = iwt.Addr(pubRaw)
	stacks[prvHex] = e
	return e.DialTCP(&net.TCPAddr{IP: ipTheir, Port: port})
}

type OOBState struct {
	c      *ycore.Core
	subnet yaddr.Subnet
}

func (state *OOBState) Handler(fromKey, toKey ed25519.PublicKey, data []byte) {
	if len(data) != 1+ed25519.SignatureSize {
		return
	}
	if data[0] == typeKeyLookup {
		snet := *yaddr.SubnetForKey(toKey)
		sig := data[1:]
		if snet == state.subnet && ed25519.Verify(fromKey, toKey[:], sig) {
			state.c.SendOutOfBand(fromKey, append(
				[]byte{typeKeyResponse},
				ed25519.Sign(state.c.PrivateKey(), fromKey[:])...,
			))
		}
	}
}

func NewListener(aliases map[string]string, in string) (net.Listener, error) {
	// yggdrasils://PRV[:PORT]?[bind=BIND][&pub=PUB][&peer=PEER][&mcast=REGEX[:PORT]]
	u, err := url.Parse(in)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "yggdrasils" {
		return nil, errors.New("expected yggdrasils:// scheme")
	}

	prvHex := u.Hostname()
	if v, ok := aliases[prvHex]; ok {
		prvHex = v
	}
	prvRaw, err := hex.DecodeString(prvHex)
	if err != nil {
		return nil, err
	}
	if len(prvRaw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	port := DefaultPort
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
	}

	values := u.Query()
	var binds []string
	for _, bind := range values["bind"] {
		if v, ok := aliases[bind]; ok {
			bind = v
		}
		binds = append(binds, bind)
	}
	var pubs []string
	for _, pub := range values["pub"] {
		if v, ok := aliases[pub]; ok {
			pub = v
		}
		pubs = append(pubs, pub)
	}
	var peers []string
	for _, peer := range values["peer"] {
		if v, ok := aliases[peer]; ok {
			peer = v
		}
		peers = append(peers, peer)
	}
	var mcasts []string
	for _, mcast := range values["mcast"] {
		if v, ok := aliases[mcast]; ok {
			mcast = v
		}
		mcasts = append(mcasts, mcast)
	}

	addrOur := yaddr.AddrForKey(ed25519.PublicKey(
		prvRaw[len(prvRaw)-ed25519.PublicKeySize:],
	))
	ipOur := net.IP(addrOur[:])

	stacksM.Lock()
	defer stacksM.Unlock()
	e, ok := stacks[prvHex]
	if ok {
		return e.ListenTCP(&net.TCPAddr{IP: ipOur, Port: port})
	}
	cfg := ycfg.NodeConfig{
		PrivateKey:        prvHex,
		Listen:            binds,
		AllowedPublicKeys: pubs,
		Peers:             peers,
		NodeInfo:          map[string]interface{}{"name": "NNCP"},
		NodeInfoPrivacy:   true,
	}
	core, err := ycoreStart(&cfg, port, mcasts)
	if err != nil {
		return nil, err
	}
	oobState := OOBState{core, *yaddr.SubnetForKey(core.PublicKey())}
	if err := core.SetOutOfBandHandler(oobState.Handler); err != nil {
		core.Stop()
		return nil, err
	}
	e, err = NewTCPIPEndpoint(core, ipOur, uint32(core.MTU()))
	if err != nil {
		core.Stop()
		return nil, err
	}
	ln, err := e.ListenTCP(&net.TCPAddr{IP: ipOur, Port: port})
	if err != nil {
		e.Close()
		core.Stop()
		return nil, err
	}
	stacks[prvHex] = e
	return ln, nil
}
