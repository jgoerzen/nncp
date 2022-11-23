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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gorhill/cronexpr"
	nncpYggdrasil "go.cypherpunks.ru/nncp/v8/yggdrasil"
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
	WhenTxExists   bool
	NoCK           bool
	MCDIgnore      bool

	AutoToss       bool
	AutoTossDoSeen bool
	AutoTossNoFile bool
	AutoTossNoFreq bool
	AutoTossNoExec bool
	AutoTossNoTrns bool
	AutoTossNoArea bool
	AutoTossNoACK  bool
}

func (ctx *Ctx) CallNode(
	node *Node,
	addrs []string,
	nice uint8,
	xxOnly TRxTx,
	rxRate, txRate int,
	onlineDeadline, maxOnlineTime time.Duration,
	listOnly bool,
	noCK bool,
	onlyPkts map[[MTHSize]byte]bool,
) (isGood bool) {
	for _, addr := range addrs {
		les := LEs{{"Node", node.Id}, {"Addr", addr}}
		ctx.LogD("calling", les, func(les LEs) string {
			return fmt.Sprintf("Calling %s (%s)", node.Name, addr)
		})
		var conn ConnDeadlined
		var err error
		if addr[0] == '|' {
			conn, err = NewPipeConn(addr[1:])
		} else if addr == UCSPITCPClient {
			ucspiConn := UCSPIConn{R: os.NewFile(6, "R"), W: os.NewFile(7, "W")}
			if ucspiConn.R == nil {
				err = errors.New("no 6 file descriptor")
			}
			if ucspiConn.W == nil {
				err = errors.New("no 7 file descriptor")
			}
			conn = ucspiConn
			addr = UCSPITCPRemoteAddr()
			if addr == "" {
				addr = UCSPITCPClient
			}
		} else if strings.HasPrefix(addr, "yggdrasilc://") {
			conn, err = nncpYggdrasil.NewConn(ctx.YggdrasilAliases, addr)
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			ctx.LogE("calling", les, err, func(les LEs) string {
				return fmt.Sprintf("Calling %s (%s)", node.Name, addr)
			})
			continue
		}
		ctx.LogD("call-connected", les, func(les LEs) string {
			return fmt.Sprintf("Connected %s (%s)", node.Name, addr)
		})
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
			NoCK:           noCK,
			onlyPkts:       onlyPkts,
		}
		if err = state.StartI(conn); err == nil {
			ctx.LogI("call-started", les, func(les LEs) string {
				return fmt.Sprintf("Connection to %s (%s)", node.Name, addr)
			})
			isGood = state.Wait()
			ctx.LogI("call-finished", append(
				les,
				LE{"Duration", int64(state.Duration.Seconds())},
				LE{"RxBytes", state.RxBytes},
				LE{"RxSpeed", state.RxSpeed},
				LE{"TxBytes", state.TxBytes},
				LE{"TxSpeed", state.TxSpeed},
			), func(les LEs) string {
				return fmt.Sprintf(
					"Finished call with %s (%d:%d:%d): %s received (%s/sec), %s transferred (%s/sec)",
					node.Name,
					int(state.Duration.Hours()),
					int(state.Duration.Minutes()),
					int(state.Duration.Seconds())%60,
					humanize.IBytes(uint64(state.RxBytes)),
					humanize.IBytes(uint64(state.RxSpeed)),
					humanize.IBytes(uint64(state.TxBytes)),
					humanize.IBytes(uint64(state.TxSpeed)),
				)
			})
			conn.Close()
			break
		} else {
			ctx.LogE("call-started", les, err, func(les LEs) string {
				return fmt.Sprintf("Connection to %s (%s)", node.Name, addr)
			})
			conn.Close()
		}
	}
	return
}
