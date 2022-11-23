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

// Show queued NNCP Rx/Tx stats.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-stat -- show queued Rx/Tx stats\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [-pkt] [-node NODE]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func jobPrint(xx nncp.TRxTx, job nncp.Job, suffix string) {
	fmt.Printf(
		"\t%s %s%s %s (nice: %s)\n",
		string(xx),
		nncp.Base32Codec.EncodeToString(job.HshValue[:]), suffix,
		humanize.IBytes(uint64(job.Size)),
		nncp.NicenessFmt(job.PktEnc.Nice),
	)
}

func main() {
	var (
		showPkt   = flag.Bool("pkt", false, "Show packets listing")
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		spoolPath = flag.String("spool", "", "Override path to spool")
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, "", false, false, false, *debug)
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
		fmt.Println(node.Name)
		rxNums := make(map[uint8]int)
		rxBytes := make(map[uint8]int64)
		noCKNums := make(map[uint8]int)
		noCKBytes := make(map[uint8]int64)
		partNums := 0
		partBytes := int64(0)
		for job := range ctx.Jobs(node.Id, nncp.TRx) {
			if *showPkt {
				jobPrint(nncp.TRx, job, "")
			}
			rxNums[job.PktEnc.Nice] = rxNums[job.PktEnc.Nice] + 1
			rxBytes[job.PktEnc.Nice] = rxBytes[job.PktEnc.Nice] + job.Size
		}
		for job := range ctx.JobsNoCK(node.Id) {
			if *showPkt {
				jobPrint(nncp.TRx, job, ".nock")
			}
			noCKNums[job.PktEnc.Nice] = noCKNums[job.PktEnc.Nice] + 1
			noCKBytes[job.PktEnc.Nice] = noCKBytes[job.PktEnc.Nice] + job.Size
		}
		for job := range ctx.JobsPart(node.Id) {
			if *showPkt {
				fmt.Printf(
					"\t%s %s.part %s\n",
					string(nncp.TRx),
					nncp.Base32Codec.EncodeToString(job.HshValue[:]),
					humanize.IBytes(uint64(job.Size)),
				)
			}
			partNums++
			partBytes += job.Size
		}
		txNums := make(map[uint8]int)
		txBytes := make(map[uint8]int64)
		for job := range ctx.Jobs(node.Id, nncp.TTx) {
			if *showPkt {
				jobPrint(nncp.TTx, job, "")
			}
			txNums[job.PktEnc.Nice] = txNums[job.PktEnc.Nice] + 1
			txBytes[job.PktEnc.Nice] = txBytes[job.PktEnc.Nice] + job.Size
		}
		var nice uint8
		if partNums > 0 {
			fmt.Printf(
				"\tpart: % 10s, % 3d pkts\n",
				humanize.IBytes(uint64(partBytes)), partNums,
			)
		}
		for nice = 1; nice > 0; nice++ {
			rxNum, rxExists := rxNums[nice]
			txNum, txExists := txNums[nice]
			noCKNum, noCKExists := noCKNums[nice]
			if !(rxExists || txExists || noCKExists) {
				continue
			}
			fmt.Printf(
				"\tnice:% 4s | Rx: % 10s, % 3d pkts | Tx: % 10s, % 3d pkts",
				nncp.NicenessFmt(nice),
				humanize.IBytes(uint64(rxBytes[nice])),
				rxNum,
				humanize.IBytes(uint64(txBytes[nice])),
				txNum,
			)
			if noCKExists {
				fmt.Printf(
					" | NoCK: % 10s, % 3d pkts",
					humanize.IBytes(uint64(noCKBytes[nice])),
					noCKNum,
				)
			}
			fmt.Printf("\n")
		}
	}
}
