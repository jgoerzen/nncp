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

package nncp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
)

const (
	MCDPort = 5400
)

type MCD struct {
	Magic  [8]byte
	Sender *NodeId
}

type MCDAddr struct {
	Addr     net.UDPAddr
	lastSeen time.Time
}

var (
	mcdIP           = net.ParseIP("ff02::4e4e:4350")
	mcdAddrLifetime = 2 * time.Minute

	mcdPktSize int
	MCDAddrs   map[NodeId][]*MCDAddr
	MCDAddrsM  sync.RWMutex
)

func init() {
	nodeId := new(NodeId)
	var buf bytes.Buffer
	mcd := MCD{Sender: nodeId}
	if _, err := xdr.Marshal(&buf, mcd); err != nil {
		panic(err)
	}
	mcdPktSize = buf.Len()

	MCDAddrs = make(map[NodeId][]*MCDAddr)
	go func() {
		for {
			time.Sleep(time.Minute)
			MCDAddrsM.Lock()
			now := time.Now()
			for nodeId, addrs := range MCDAddrs {
				addrsAlive := make([]*MCDAddr, 0, len(addrs))
				for _, addr := range addrs {
					if !addr.lastSeen.Add(mcdAddrLifetime).Before(now) {
						addrsAlive = append(addrsAlive, addr)
					}
				}
				MCDAddrs[nodeId] = addrsAlive
			}
			MCDAddrsM.Unlock()
		}
	}()
}

func (ctx *Ctx) MCDRx(ifiName string) error {
	ifi, err := net.InterfaceByName(ifiName)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: mcdIP, Port: MCDPort, Zone: ifiName}
	conn, err := net.ListenMulticastUDP("udp", ifi, addr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, mcdPktSize)
		var n int
		var mcd MCD
	ListenCycle:
		for {
			les := LEs{{"If", ifiName}}
			n, addr, err = conn.ReadFromUDP(buf)
			if err != nil {
				ctx.LogE("mcd", les, err, func(les LEs) string {
					return fmt.Sprintf("MCD Rx %s/%d", ifiName, MCDPort)
				})
				continue
			}
			if n != mcdPktSize {
				ctx.LogD("mcd", les, func(les LEs) string {
					return fmt.Sprintf(
						"MCD Rx %s/%d: got packet with invalid size",
						ifiName, MCDPort,
					)
				})
				continue
			}
			_, err = xdr.Unmarshal(bytes.NewReader(buf[:n]), &mcd)
			if err != nil {
				ctx.LogD("mcd", les, func(les LEs) string {
					return fmt.Sprintf(
						"MCD Rx %s/%d: can not unmarshal: %s",
						ifiName, MCDPort, err,
					)
				})
				continue
			}
			if mcd.Magic != MagicNNCPDv1.B {
				ctx.LogD("mcd", les, func(les LEs) string {
					return fmt.Sprintf(
						"MCD Rx %s/%d: unexpected magic: %s",
						ifiName, MCDPort, hex.EncodeToString(mcd.Magic[:]),
					)
				})
				continue
			}
			node, known := ctx.Neigh[*mcd.Sender]
			if known {
				les = append(les, LE{"Node", node.Id})
				ctx.LogD("mcd", les, func(les LEs) string {
					return fmt.Sprintf(
						"MCD Rx %s/%d: %s: node %s",
						ifiName, MCDPort, addr, node.Name,
					)
				})
			} else {
				ctx.LogD("mcd", les, func(les LEs) string {
					return fmt.Sprintf(
						"MCD Rx %s/%d: %s: unknown node %s",
						ifiName, MCDPort, addr, node.Id.String(),
					)
				})
				continue
			}
			MCDAddrsM.RLock()
			for _, mcdAddr := range MCDAddrs[*mcd.Sender] {
				if mcdAddr.Addr.IP.Equal(addr.IP) &&
					mcdAddr.Addr.Port == addr.Port &&
					mcdAddr.Addr.Zone == addr.Zone {
					mcdAddr.lastSeen = time.Now()
					MCDAddrsM.RUnlock()
					continue ListenCycle
				}
			}
			MCDAddrsM.RUnlock()
			MCDAddrsM.Lock()
			MCDAddrs[*mcd.Sender] = append(
				MCDAddrs[*mcd.Sender],
				&MCDAddr{Addr: *addr, lastSeen: time.Now()},
			)
			MCDAddrsM.Unlock()
			ctx.LogI("mcd-add", les, func(les LEs) string {
				return fmt.Sprintf("MCD discovered %s's address: %s", node.Name, addr)
			})
		}
	}()
	return nil
}

func (ctx *Ctx) MCDTx(ifiName string, port int, interval time.Duration) error {
	ifi, err := net.InterfaceByName(ifiName)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: mcdIP, Port: port, Zone: ifiName}
	conn, err := net.ListenMulticastUDP("udp", ifi, addr)
	if err != nil {
		return err
	}

	dst := &net.UDPAddr{IP: mcdIP, Port: MCDPort, Zone: ifiName}
	var buf bytes.Buffer
	mcd := MCD{Magic: MagicNNCPDv1.B, Sender: ctx.Self.Id}
	if _, err := xdr.Marshal(&buf, mcd); err != nil {
		panic(err)
	}
	if interval == 0 {
		_, err = conn.WriteTo(buf.Bytes(), dst)
		return err
	}
	go func() {
		les := LEs{{"If", ifiName}}
		for {
			ctx.LogD("mcd", les, func(les LEs) string {
				return fmt.Sprintf(
					"MCD Tx %s/%d/%d",
					ifiName, MCDPort, port,
				)
			})
			_, err = conn.WriteTo(buf.Bytes(), dst)
			if err != nil {
				ctx.LogE("mcd", les, err, func(les LEs) string {
					return fmt.Sprintf("MCD on %s/%d/%d", ifiName, MCDPort, port)
				})
			}
			time.Sleep(interval)
		}
	}()
	return nil
}
