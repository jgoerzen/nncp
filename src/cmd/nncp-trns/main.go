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

// Wrap existing encrypted packet to transition ones.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-trns -- transit existing encrypted packet\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -via NODEx[,...] NODE:PKT\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       (to transit SPOOL/NODE/tx/PKT)\n")
	fmt.Fprintf(os.Stderr, "       %s [options] -via NODEx[,...] /path/to/PKT\nOptions:\n",
		os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath     = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFile), "Outbound packet niceness")
		viaOverride = flag.String("via", "", "Override Via path to destination node")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
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
	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
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

	var pktPath string
	var pktName string
	if _, err = os.Stat(flag.Arg(0)); err == nil {
		pktPath = flag.Arg(0)
		pktName = filepath.Base(pktPath)
	} else {
		splitted := strings.Split(flag.Arg(0), ":")
		if len(splitted) != 2 {
			log.Fatalln("Invalid NODE:PKT specification")
		}
		node, err := ctx.FindNode(splitted[0])
		if err != nil {
			log.Fatalln("Invalid NODE specified:", err)
		}
		pktPath = filepath.Join(
			ctx.Spool, node.Id.String(), string(nncp.TTx), splitted[1],
		)
		pktName = filepath.Base(splitted[1])
	}

	fd, err := os.Open(pktPath)
	if err != nil {
		log.Fatalln(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		log.Fatalln(err)
	}
	pktEnc, _, err := ctx.HdrRead(fd)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err = fd.Seek(0, io.SeekStart); err != nil {
		log.Fatalln(err)
	}

	node := ctx.Neigh[*pktEnc.Recipient]
	nncp.ViaOverride(*viaOverride, ctx, node)
	via := node.Via[:len(node.Via)-1]
	node = ctx.Neigh[*node.Via[len(node.Via)-1]]
	node.Via = via

	pktTrns, err := nncp.NewPkt(nncp.PktTypeTrns, 0, pktEnc.Recipient[:])
	if err != nil {
		panic(err)
	}
	if _, _, _, err = ctx.Tx(
		node,
		pktTrns,
		nice,
		fi.Size(), 0, nncp.MaxFileSize,
		fd,
		pktName,
		nil,
	); err != nil {
		log.Fatalln(err)
	}
}
