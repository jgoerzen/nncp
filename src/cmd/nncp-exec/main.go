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

// Send execution command via NNCP.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-exec -- send execution command\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE HANDLE [ARG0 ARG1 ...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] %s:AREA HANDLE [ARG0 ARG1 ...]\nOptions:\n",
		os.Args[0], nncp.AreaDir)
	flag.PrintDefaults()
}

func main() {
	var (
		noCompress   = flag.Bool("nocompress", false, "Do not compress input data")
		cfgPath      = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw      = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceExec), "Outbound packet niceness")
		replyNiceRaw = flag.String("replynice", nncp.NicenessFmt(nncp.DefaultNiceFile), "Possible reply packet niceness")
		minSize      = flag.Uint64("minsize", 0, "Minimal required resulting packet size, in KiB")
		argMaxSize   = flag.Uint64("maxsize", 0, "Maximal allowable resulting packet size, in KiB")
		viaOverride  = flag.String("via", "", "Override Via path to destination node")
		spoolPath    = flag.String("spool", "", "Override path to spool")
		logPath      = flag.String("log", "", "Override path to logfile")
		quiet        = flag.Bool("quiet", false, "Print only errors")
		showPrgrs    = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs    = flag.Bool("noprogress", false, "Omit progress showing")
		debug        = flag.Bool("debug", false, "Print debug messages")
		version      = flag.Bool("version", false, "Print version information")
		warranty     = flag.Bool("warranty", false, "Print warranty information")
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
	if flag.NArg() < 2 {
		usage()
		os.Exit(1)
	}
	nice, err := nncp.NicenessParse(*niceRaw)
	if err != nil {
		log.Fatalln(err)
	}
	replyNice, err := nncp.NicenessParse(*replyNiceRaw)
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

	var areaId *nncp.AreaId
	var node *nncp.Node
	if strings.HasPrefix(flag.Arg(0), nncp.AreaDir+":") {
		areaId = ctx.AreaName2Id[flag.Arg(0)[len(nncp.AreaDir)+1:]]
		if areaId == nil {
			log.Fatalln("Unknown area specified")
		}
		node = ctx.Neigh[*ctx.SelfId]
	} else {
		node, err = ctx.FindNode(flag.Arg(0))
		if err != nil {
			log.Fatalln("Invalid NODE specified:", err)
		}
	}

	maxSize := int64(nncp.MaxFileSize)
	if *argMaxSize > 0 {
		maxSize = int64(*argMaxSize) * 1024
	}

	nncp.ViaOverride(*viaOverride, ctx, node)
	ctx.Umask()

	if err = ctx.TxExec(
		node,
		nice,
		replyNice,
		flag.Args()[1],
		flag.Args()[2:],
		bufio.NewReaderSize(os.Stdin, nncp.MTHBlockSize),
		int64(*minSize)*1024,
		maxSize,
		*noCompress,
		areaId,
	); err != nil {
		log.Fatalln(err)
	}
}
