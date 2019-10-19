/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

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
	"strconv"

	"github.com/gorhill/cronexpr"
)

type Call struct {
	Cron           *cronexpr.Expression
	Nice           uint8
	Xx             TRxTx
	RxRate         int
	TxRate         int
	Addr           *string
	OnlineDeadline uint
	MaxOnlineTime  uint
}

func (ctx *Ctx) CallNode(
	node *Node,
	addrs []string,
	nice uint8,
	xxOnly TRxTx,
	rxRate, txRate int,
	onlineDeadline, maxOnlineTime uint,
	listOnly bool,
	onlyPkts map[[32]byte]bool,
) (isGood bool) {
	for _, addr := range addrs {
		sds := SDS{"node": node.Id, "addr": addr}
		ctx.LogD("call", sds, "dialing")
		conn, err := net.Dial("tcp", addr)
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
				"duration": strconv.FormatInt(int64(state.Duration.Seconds()), 10),
				"rxbytes":  strconv.FormatInt(state.RxBytes, 10),
				"txbytes":  strconv.FormatInt(state.TxBytes, 10),
				"rxspeed":  strconv.FormatInt(state.RxSpeed, 10),
				"txspeed":  strconv.FormatInt(state.TxSpeed, 10),
			}, "")
			isGood = true
			conn.Close()
			break
		} else {
			ctx.LogE("call-start", SdsAdd(sds, SDS{"err": err}), "")
			conn.Close()
		}
	}
	return
}
