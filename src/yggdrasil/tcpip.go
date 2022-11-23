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

Code below is heavily based on Wireguard's MIT licenced
golang.zx2c4.com/wireguard/tun/netstack.
*/

package yggdrasil

import (
	"fmt"
	"log"
	"net"

	iwt "github.com/Arceliar/ironwood/types"
	yaddr "github.com/yggdrasil-network/yggdrasil-go/src/address"
	"golang.org/x/crypto/ed25519"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const IPv6HdrSize = 40

type TCPIPEndpoint struct {
	mtu      uint32
	s        *stack.Stack
	pc       net.PacketConn
	d        stack.NetworkDispatcher
	readBuf  []byte
	writeBuf []byte
	ip       yaddr.Address
	ipToAddr map[yaddr.Address]net.Addr
	pubToIP  map[[ed25519.PublicKeySize]byte]yaddr.Address
}

func (e *TCPIPEndpoint) Attach(dispatcher stack.NetworkDispatcher) { e.d = dispatcher }

func (e *TCPIPEndpoint) IsAttached() bool { return e.d != nil }

func (e *TCPIPEndpoint) MTU() uint32 { return e.mtu }

func (*TCPIPEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }

func (*TCPIPEndpoint) MaxHeaderLength() uint16 { return 0 }

func (*TCPIPEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (*TCPIPEndpoint) Wait() {}

func (e *TCPIPEndpoint) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	v := pkt.ToView()
	n, err := v.Read(e.writeBuf)
	if err != nil {
		log.Println(err)
		return &tcpip.ErrAborted{}
	}
	copy(e.ip[:], e.writeBuf[IPv6HdrSize-len(e.ip):IPv6HdrSize])
	addr, ok := e.ipToAddr[e.ip]
	if !ok {
		log.Println("no address found:", e.ip)
		return nil
	}
	_, err = e.pc.WriteTo(e.writeBuf[:n], addr)
	if err != nil {
		log.Println(err)
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (e *TCPIPEndpoint) WritePackets(pbs stack.PacketBufferList) (int, tcpip.Error) {
	for i, pb := range pbs.AsSlice() {
		err := e.WritePacket(pb)
		if err != nil {
			return i + 1, err
		}
	}
	return len(pbs.AsSlice()), nil
}

func (e *TCPIPEndpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	panic("not implemented")
}

func (*TCPIPEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (e *TCPIPEndpoint) AddHeader(*stack.PacketBuffer) {}

func convertToFullAddr(ip net.IP, port int) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(ip),
		Port: uint16(port),
	}, ipv6.ProtocolNumber
}

func (e *TCPIPEndpoint) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		panic("not implemented")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.DialTCP(e.s, fa, pn)
}

func (e *TCPIPEndpoint) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		panic("not implemented")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.ListenTCP(e.s, fa, pn)
}

func (e *TCPIPEndpoint) Close() error {
	e.s.RemoveNIC(1)
	return nil
}

func NewTCPIPEndpoint(
	pc net.PacketConn,
	ipOur net.IP,
	mtu uint32,
) (*TCPIPEndpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	e := TCPIPEndpoint{
		mtu:      mtu,
		s:        s,
		pc:       pc,
		readBuf:  make([]byte, 1<<16),
		writeBuf: make([]byte, 1<<16),
		ipToAddr: make(map[yaddr.Address]net.Addr),
		pubToIP:  make(map[[ed25519.PublicKeySize]byte]yaddr.Address),
	}
	if err := s.CreateNIC(1, &e); err != nil {
		return nil, fmt.Errorf("%+v", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.Address(ipOur).WithPrefix(),
	}
	if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("%+v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	go func() {
		var n int
		var from net.Addr
		var err error
		var pub [ed25519.PublicKeySize]byte
		for {
			n, from, err = pc.ReadFrom(e.readBuf)
			if err != nil {
				log.Println(err)
				break
			}
			copy(pub[:], from.(iwt.Addr))
			ip, ok := e.pubToIP[pub]
			if !ok {
				copy(ip[:], yaddr.AddrForKey(ed25519.PublicKey(pub[:]))[:])
				e.pubToIP[pub] = ip
				e.ipToAddr[ip] = from
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(e.readBuf[:n]),
			})
			e.d.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
		}
	}()
	return &e, nil
}
