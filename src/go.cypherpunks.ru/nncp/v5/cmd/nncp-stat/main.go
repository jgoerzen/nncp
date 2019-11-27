/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

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

// Show queued NNCP Rx/Tx stats.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v5"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-stat -- show queued Rx/Tx stats\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		spoolPath = flag.String("spool", "", "Override path to spool")
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, "", false, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

	nodeNames := make([]string, 0, len(ctx.Neigh))
	nodeNameToNode := make(map[string]*nncp.Node, len(ctx.Neigh))
	for _, node := range ctx.Neigh {
		nodeNames = append(nodeNames, node.Name)
		nodeNameToNode[node.Name] = node
	}
	sort.Strings(nodeNames)

	ctx.Umask()
	var node *nncp.Node
	for _, nodeName := range nodeNames {
		node = nodeNameToNode[nodeName]
		if nodeOnly != nil && *node.Id != *nodeOnly.Id {
			continue
		}
		rxNums := make(map[uint8]int)
		rxBytes := make(map[uint8]int64)
		for job := range ctx.Jobs(node.Id, nncp.TRx) {
			job.Fd.Close()
			rxNums[job.PktEnc.Nice] = rxNums[job.PktEnc.Nice] + 1
			rxBytes[job.PktEnc.Nice] = rxBytes[job.PktEnc.Nice] + job.Size
		}
		txNums := make(map[uint8]int)
		txBytes := make(map[uint8]int64)
		for job := range ctx.Jobs(node.Id, nncp.TTx) {
			job.Fd.Close()
			txNums[job.PktEnc.Nice] = txNums[job.PktEnc.Nice] + 1
			txBytes[job.PktEnc.Nice] = txBytes[job.PktEnc.Nice] + job.Size
		}
		fmt.Println(node.Name)
		var nice uint8
		for nice = 1; nice > 0; nice++ {
			rxNum, rxExists := rxNums[nice]
			txNum, txExists := txNums[nice]
			if !(rxExists || txExists) {
				continue
			}
			fmt.Printf(
				"\tnice:% 4s | Rx: % 10s, % 3d pkts | Tx: % 10s, % 3d pkts\n",
				nncp.NicenessFmt(nice),
				humanize.IBytes(uint64(rxBytes[nice])),
				rxNum,
				humanize.IBytes(uint64(txBytes[nice])),
				txNum,
			)
		}
	}
}
