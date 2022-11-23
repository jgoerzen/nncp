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

// Process inbound NNCP packets.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-toss -- process inbound packets\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		dryRun    = flag.Bool("dryrun", false, "Do not actually write any tossed data")
		doSeen    = flag.Bool("seen", false, "Create seen/ files")
		cycle     = flag.Uint("cycle", 0, "Repeat tossing after N seconds in infinite loop")
		noFile    = flag.Bool("nofile", false, "Do not process \"file\" packets")
		noFreq    = flag.Bool("nofreq", false, "Do not process \"freq\" packets")
		noExec    = flag.Bool("noexec", false, "Do not process \"exec\" packets")
		noTrns    = flag.Bool("notrns", false, "Do not process \"transitional\" packets")
		noArea    = flag.Bool("noarea", false, "Do not process \"area\" packets")
		noACK     = flag.Bool("noack", false, "Do not process \"ack\" packets")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")
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

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

	ctx.Umask()

	if *cycle == 0 {
		isBad := false
		for nodeId, node := range ctx.Neigh {
			if nodeOnly != nil && nodeId != *nodeOnly.Id {
				continue
			}
			isBad = ctx.Toss(
				node.Id,
				nncp.TRx,
				nice,
				*dryRun, *doSeen, *noFile, *noFreq, *noExec, *noTrns, *noArea, *noACK,
			) || isBad
			if nodeId == *ctx.SelfId {
				isBad = ctx.Toss(
					node.Id,
					nncp.TTx,
					nice,
					*dryRun, false, true, true, true, true, *noArea, *noACK,
				) || isBad
			}
		}
		if isBad {
			os.Exit(1)
		}
		return
	}

	nodeIds := make(chan *nncp.NodeId)
	for nodeId, node := range ctx.Neigh {
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			continue
		}
		dw, err := ctx.NewDirWatcher(
			filepath.Join(ctx.Spool, node.Id.String(), string(nncp.TRx)),
			time.Second*time.Duration(*cycle),
		)
		if err != nil {
			log.Fatalln(err)
		}
		go func(nodeId *nncp.NodeId) {
			for range dw.C {
				nodeIds <- nodeId
			}
		}(node.Id)
	}
	for nodeId := range nodeIds {
		ctx.Toss(
			nodeId,
			nncp.TRx,
			nice,
			*dryRun, *doSeen, *noFile, *noFreq, *noExec, *noTrns, *noArea, *noACK,
		)
		if *nodeId == *ctx.SelfId {
			ctx.Toss(
				nodeId,
				nncp.TTx,
				nice,
				*dryRun, false, true, true, true, true, *noArea, *noACK,
			)
		}
	}
}
