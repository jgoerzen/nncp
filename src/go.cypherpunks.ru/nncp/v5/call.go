/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2020 Sergey Matveev <stargrave@stargrave.org>

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
	"net"
	"time"

	"github.com/gorhill/cronexpr"
)

type Call struct {
	Cron           *cronexpr.Expression
	Nice           uint8
	Xx             TRxTx
	RxRate         int
	TxRate         int
	Addr           *string
	OnlineDeadline time.Duration
	MaxOnlineTime  time.Duration
}

func (ctx *Ctx) CallNode(
	node *Node,
	addrs []string,
	nice uint8,
	xxOnly TRxTx,
	rxRate, txRate int,
	onlineDeadline, maxOnlineTime time.Duration,
	listOnly bool,
	onlyPkts map[[32]byte]bool,
) (isGood bool) {
	for _, addr := range addrs {
		sds := SDS{"node": node.Id, "addr": addr}
		ctx.LogD("call", sds, "dialing")
		var conn ConnDeadlined
		var err error
		if addr[0] == '|' {
			conn, err = NewPipeConn(addr[1:])
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			ctx.LogD("call", SdsAdd(sds, SDS{"err": err}), "dialing")
			continue
		}
		ctx.LogD("call", sds, "connected")
		state := SPState{
			Ctx:            ctx,
			Node:           node,
			Nice:           nice,
			onlineDeadline: onlineDeadline,
			maxOnlineTime:  maxOnlineTime,
			xxOnly:         xxOnly,
			rxRate:         rxRate,
			txRate:         txRate,
			listOnly:       listOnly,
			onlyPkts:       onlyPkts,
		}
		if err = state.StartI(conn); err == nil {
			ctx.LogI("call-start", sds, "connected")
			state.Wait()
			ctx.LogI("call-finish", SDS{
				"node":     state.Node.Id,
				"duration": int64(state.Duration.Seconds()),
				"rxbytes":  state.RxBytes,
				"txbytes":  state.TxBytes,
				"rxspeed":  state.RxSpeed,
				"txspeed":  state.TxSpeed,
			}, "")
			isGood = true
			conn.Close() // #nosec G104
			break
		} else {
			ctx.LogE("call-start", sds, err, "")
			conn.Close() // #nosec G104
		}
	}
	return
}
