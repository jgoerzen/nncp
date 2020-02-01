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

// Send file via NNCP.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go.cypherpunks.ru/nncp/v5"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-file -- send file\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] SRC NODE:[DST]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
If SRC equals to -, then read data from stdin to temporary file.

-minsize/-chunked take NODE's freq.minsize/freq.chunked configuration
options by default. You can forcefully turn them off by specifying 0 value.
`)
}

func main() {
	var (
		cfgPath      = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw      = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFile), "Outbound packet niceness")
		argMinSize   = flag.Int64("minsize", -1, "Minimal required resulting packet size, in KiB")
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

	splitted := strings.SplitN(flag.Arg(1), ":", 2)
	if len(splitted) != 2 {
		usage()
		os.Exit(1)
	}
	node, err := ctx.FindNode(splitted[0])
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}

	nncp.ViaOverride(*viaOverride, ctx, node)
	ctx.Umask()

	var minSize int64
	if *argMinSize < 0 {
		minSize = node.FreqMinSize
	} else if *argMinSize > 0 {
		minSize = *argMinSize * 1024
	}

	var chunkSize int64
	if *argChunkSize < 0 {
		chunkSize = node.FreqChunked
	} else if *argChunkSize > 0 {
		chunkSize = *argChunkSize * 1024
	}
	if chunkSize == 0 {
		chunkSize = nncp.MaxFileSize
	}

	if err = ctx.TxFile(
		node,
		nice,
		flag.Arg(0),
		splitted[1],
		chunkSize,
		minSize,
		nncp.MaxFileSize,
	); err != nil {
		log.Fatalln(err)
	}
}
