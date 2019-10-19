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

// NNCP TCP daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"cypherpunks.ru/nncp"
	"golang.org/x/net/netutil"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-daemon -- TCP daemon\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

type InetdConn struct {
	r *os.File
	w *os.File
}

func (ic *InetdConn) Read(p []byte) (n int, err error) {
	return ic.r.Read(p)
}

func (ic *InetdConn) Write(p []byte) (n int, err error) {
	return ic.w.Write(p)
}

func (ic *InetdConn) SetReadDeadline(t time.Time) error {
	return ic.r.SetReadDeadline(t)
}

func (ic *InetdConn) SetWriteDeadline(t time.Time) error {
	return ic.w.SetWriteDeadline(t)
}

func performSP(ctx *nncp.Ctx, conn nncp.ConnDeadlined, nice uint8) {
	state := nncp.SPState{
		Ctx:  ctx,
		Nice: nice,
	}
	if err := state.StartR(conn); err == nil {
		ctx.LogI("call-start", nncp.SDS{"node": state.Node.Id}, "connected")
		state.Wait()
		ctx.LogI("call-finish", nncp.SDS{
			"node":     state.Node.Id,
			"duration": strconv.FormatInt(int64(state.Duration.Seconds()), 10),
			"rxbytes":  strconv.FormatInt(state.RxBytes, 10),
			"txbytes":  strconv.FormatInt(state.TxBytes, 10),
			"rxspeed":  strconv.FormatInt(state.RxSpeed, 10),
			"txspeed":  strconv.FormatInt(state.TxSpeed, 10),
		}, "")
	} else {
		nodeId := "unknown"
		if state.Node != nil {
			nodeId = state.Node.Id.String()
		}
		ctx.LogE("call-start", nncp.SDS{"node": nodeId, "err": err}, "")
	}
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		bind      = flag.String("bind", "[::]:5400", "Address to bind to")
		inetd     = flag.Bool("inetd", false, "Is it started as inetd service")
		maxConn   = flag.Int("maxconn", 128, "Maximal number of simultaneous connections")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")
	)
	flag.Usage = usage
	flag.Parse()
	if *warranty {
		fmt.Println(nncp.Warranty)
		return
	}
	if *version {
		fmt.Println(nncp.VersionGet())
		return
	}
	nice, err := nncp.NicenessParse(*niceRaw)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, *logPath, *quiet, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	if ctx.Self == nil {
		log.Fatalln("Config lacks private keys")
	}

	if *inetd {
		os.Stderr.Close()
		conn := &InetdConn{os.Stdin, os.Stdout}
		performSP(ctx, conn, nice)
		return
	}

	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalln("Can not listen:", err)
	}
	ln = netutil.LimitListener(ln, *maxConn)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalln("Can not accept connection:", err)
		}
		ctx.LogD("daemon", nncp.SDS{"addr": conn.RemoteAddr()}, "accepted")
		go func(conn net.Conn) {
			performSP(ctx, conn, nice)
			conn.Close()
		}(conn)
	}
}
