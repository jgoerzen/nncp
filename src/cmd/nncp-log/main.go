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

// Read NNCP logs.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"go.cypherpunks.ru/nncp/v8"
	"go.cypherpunks.ru/recfile"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-log -- read logs\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		logPath  = flag.String("log", "", "Override path to logfile")
		debug    = flag.Bool("debug", false, "Print debug messages")
		version  = flag.Bool("version", false, "Print version information")
		warranty = flag.Bool("warranty", false, "Print warranty information")
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, "", *logPath, false, false, false, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}

	fd, err := os.Open(ctx.LogPath)
	if err != nil {
		log.Fatalln("Can not open log:", err)
	}
	r := recfile.NewReader(fd)
	for {
		le, err := r.NextMap()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalln("Can not read log:", err)
		}
		if *debug {
			fmt.Println(le)
		}
		s, err := ctx.Humanize(le)
		if err != nil {
			s = fmt.Sprintf("Can not humanize: %s\n%s", err, le)
		}
		fmt.Println(s)
	}
}
