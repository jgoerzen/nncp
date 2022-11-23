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

// Send packet receipt acknowledgement via NNCP.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-ack -- send packet receipt acknowledgement\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -all\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -node NODE[,...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -node NODE -pkt PKT\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath     = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFreq), "Outbound packet niceness")
		minSizeRaw  = flag.Uint64("minsize", 0, "Minimal required resulting packet size, in KiB")
		viaOverride = flag.String("via", "", "Override Via path to destination node (ignored with -all)")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
		doAll       = flag.Bool("all", false, "ACK all rx packet for all nodes")
		nodesRaw    = flag.String("node", "", "ACK rx packets for that node")
		pktRaw      = flag.String("pkt", "", "ACK only that packet")
		quiet       = flag.Bool("quiet", false, "Print only errors")
		showPrgrs   = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs   = flag.Bool("noprogress", false, "Omit progress showing")
		debug       = flag.Bool("debug", false, "Print debug messages")
		version     = flag.Bool("version", false, "Print version information")
		warranty    = flag.Bool("warranty", false, "Print warranty information")
	)
	log.SetFlags(log.Lshortfile)
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

	ctx, err := nncp.CtxFromCmdline(
		*cfgPath,
		*spoolPath,
		*logPath,
		*quiet,
		*showPrgrs,
		*omitPrgrs,
		*debug,
	)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	if ctx.Self == nil {
		log.Fatalln("Config lacks private keys")
	}

	ctx.Umask()
	minSize := int64(*minSizeRaw) * 1024

	var nodes []*nncp.Node
	if *nodesRaw != "" {
		for _, nodeRaw := range strings.Split(*nodesRaw, ",") {
			node, err := ctx.FindNode(nodeRaw)
			if err != nil {
				log.Fatalln("Invalid -node specified:", err)
			}
			nodes = append(nodes, node)
		}
	}
	if *doAll {
		if len(nodes) != 0 {
			usage()
			os.Exit(1)
		}
		for _, node := range ctx.Neigh {
			nodes = append(nodes, node)
		}
	} else if len(nodes) == 0 {
		usage()
		os.Exit(1)
	}

	acksCreated := os.NewFile(uintptr(4), "ACKsCreated")
	if acksCreated == nil {
		log.Fatalln("can not open FD:4")
	}

	if *pktRaw != "" {
		if len(nodes) != 1 {
			usage()
			os.Exit(1)
		}
		nncp.ViaOverride(*viaOverride, ctx, nodes[0])
		pktName, err := ctx.TxACK(nodes[0], nice, *pktRaw, minSize)
		if err != nil {
			log.Fatalln(err)
		}
		acksCreated.WriteString(nodes[0].Id.String() + "/" + pktName + "\n")
		return
	}

	isBad := false
	for _, node := range nodes {
		for job := range ctx.Jobs(node.Id, nncp.TRx) {
			pktName := filepath.Base(job.Path)
			sender := ctx.Neigh[*job.PktEnc.Sender]
			les := nncp.LEs{
				{K: "Node", V: job.PktEnc.Sender},
				{K: "Pkt", V: pktName},
			}
			logMsg := func(les nncp.LEs) string {
				return fmt.Sprintf(
					"ACKing %s/%s",
					ctx.NodeName(job.PktEnc.Sender), pktName,
				)
			}
			if sender == nil {
				err := errors.New("unknown node")
				ctx.LogE("ack-read", les, err, logMsg)
				isBad = true
				continue
			}
			fd, err := os.Open(job.Path)
			if err != nil {
				ctx.LogE("ack-read-open", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": opening" + job.Path
				})
				isBad = true
				continue
			}
			pktEnc, _, err := ctx.HdrRead(fd)
			if err != nil {
				fd.Close()
				ctx.LogE("ack-read-read", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": reading" + job.Path
				})
				isBad = true
				continue
			}
			switch pktEnc.Magic {
			case nncp.MagicNNCPEv1.B:
				err = nncp.MagicNNCPEv1.TooOld()
			case nncp.MagicNNCPEv2.B:
				err = nncp.MagicNNCPEv2.TooOld()
			case nncp.MagicNNCPEv3.B:
				err = nncp.MagicNNCPEv3.TooOld()
			case nncp.MagicNNCPEv4.B:
				err = nncp.MagicNNCPEv4.TooOld()
			case nncp.MagicNNCPEv5.B:
				err = nncp.MagicNNCPEv5.TooOld()
			case nncp.MagicNNCPEv6.B:
			default:
				err = errors.New("is not an encrypted packet")
			}
			if err != nil {
				fd.Close()
				ctx.LogE("ack-read-magic", les, err, logMsg)
				isBad = true
				continue
			}
			if _, err = fd.Seek(0, io.SeekStart); err != nil {
				fd.Close()
				ctx.LogE("ack-read-seek", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": seeking"
				})
				isBad = true
				continue
			}
			pipeR, pipeW := io.Pipe()
			go nncp.PktEncRead(
				ctx.Self,
				ctx.Neigh,
				bufio.NewReaderSize(fd, nncp.MTHBlockSize),
				pipeW, true, nil,
			)
			var pkt nncp.Pkt
			_, err = xdr.Unmarshal(pipeR, &pkt)
			fd.Close()
			pipeW.Close()
			if err != nil {
				ctx.LogE("ack-read-unmarshal", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": unmarshal"
				})
				isBad = true
				continue
			}
			if pkt.Type == nncp.PktTypeACK {
				ctx.LogI("ack-read-if-ack", les, func(les nncp.LEs) string {
					return logMsg(les) + ": it is ACK, skipping"
				})
				continue
			}
			newPktName, err := ctx.TxACK(node, nice, pktName, minSize)
			if err != nil {
				log.Fatalln(err)
			}
			acksCreated.WriteString(node.Id.String() + "/" + newPktName + "\n")
		}
	}
	if isBad {
		os.Exit(1)
	}
}
