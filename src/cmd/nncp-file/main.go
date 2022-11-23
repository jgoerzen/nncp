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

// Send file via NNCP.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-file -- send file\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] SRC NODE:[DST]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] SRC %s:AREA:[DST]\nOptions:\n",
		os.Args[0], nncp.AreaDir)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
If SRC equals to "-", then data is read from stdin.
If SRC is directory, then create pax archive with its contents.

-minsize/-chunked take NODE's freq.minsize/freq.chunked configuration
options by default. You can forcefully turn them off by specifying 0 value.
`)
}

func main() {
	var (
		cfgPath      = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw      = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFile), "Outbound packet niceness")
		argMinSize   = flag.Int64("minsize", -1, "Minimal required resulting packet size, in KiB")
		argMaxSize   = flag.Uint64("maxsize", 0, "Maximal allowable resulting packets size, in KiB")
		argChunkSize = flag.Int64("chunked", -1, "Split file on specified size chunks, in KiB")
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
	if flag.NArg() != 2 {
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

	splitted := strings.Split(flag.Arg(1), ":")
	if len(splitted) < 2 {
		usage()
		os.Exit(1)
	}
	var areaId *nncp.AreaId
	var node *nncp.Node
	if splitted[0] == nncp.AreaDir {
		if len(splitted) < 3 {
			usage()
			os.Exit(1)
		}
		areaId = ctx.AreaName2Id[splitted[1]]
		if areaId == nil {
			log.Fatalln("Unknown area specified")
		}
		node = ctx.Neigh[*ctx.SelfId]
		splitted = splitted[2:]
	} else {
		node, err = ctx.FindNode(splitted[0])
		if err != nil {
			log.Fatalln("Invalid NODE specified:", err)
		}
		splitted = splitted[1:]
	}

	nncp.ViaOverride(*viaOverride, ctx, node)
	ctx.Umask()

	var chunkSize int64
	if *argChunkSize < 0 {
		chunkSize = node.FreqChunked
	} else if *argChunkSize > 0 {
		chunkSize = *argChunkSize * 1024
	}

	var minSize int64
	if *argMinSize < 0 {
		minSize = node.FreqMinSize
	} else if *argMinSize > 0 {
		minSize = *argMinSize * 1024
	}

	maxSize := int64(nncp.MaxFileSize)
	if *argMaxSize > 0 {
		maxSize = int64(*argMaxSize) * 1024
	}

	if err = ctx.TxFile(
		node,
		nice,
		flag.Arg(0),
		strings.Join(splitted, ":"),
		chunkSize,
		minSize,
		maxSize,
		areaId,
	); err != nil {
		log.Fatalln(err)
	}
}
