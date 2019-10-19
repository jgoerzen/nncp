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

// Call NNCP TCP daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"cypherpunks.ru/nncp"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-call -- call TCP daemon\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE[:ADDR] [FORCEADDR]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath     = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		rxOnly      = flag.Bool("rx", false, "Only receive packets")
		txOnly      = flag.Bool("tx", false, "Only transmit packets")
		listOnly    = flag.Bool("list", false, "Only list remote packets")
		onlyPktsRaw = flag.String("pkts", "", "Recieve only that packets, comma separated")
		rxRate      = flag.Int("rxrate", 0, "Maximal receive rate, pkts/sec")
		txRate      = flag.Int("txrate", 0, "Maximal transmit rate, pkts/sec")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
		quiet       = flag.Bool("quiet", false, "Print only errors")
		debug       = flag.Bool("debug", false, "Print debug messages")
		version     = flag.Bool("version", false, "Print version information")
		warranty    = flag.Bool("warranty", false, "Print warranty information")

		onlineDeadline = flag.Uint("onlinedeadline", 0, "Override onlinedeadline option")
		maxOnlineTime  = flag.Uint("maxonlinetime", 0, "Override maxonlinetime option")
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
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}
	nice, err := nncp.NicenessParse(*niceRaw)
	if err != nil {
		log.Fatalln(err)
	}
	if *rxOnly && *txOnly {
		log.Fatalln("-rx and -tx can not be set simultaneously")
	}

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, *logPath, *quiet, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	if ctx.Self == nil {
		log.Fatalln("Config lacks private keys")
	}

	splitted := strings.SplitN(flag.Arg(0), ":", 2)
	node, err := ctx.FindNode(splitted[0])
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}
	if node.NoisePub == nil {
		log.Fatalln("Node does not have online communication capability")
	}

	if *onlineDeadline == 0 {
		onlineDeadline = &node.OnlineDeadline
	}
	if *maxOnlineTime == 0 {
		maxOnlineTime = &node.MaxOnlineTime
	}

	var xxOnly nncp.TRxTx
	if *rxOnly {
		xxOnly = nncp.TRx
	} else if *txOnly {
		xxOnly = nncp.TTx
	}

	var addrs []string
	if flag.NArg() == 2 {
		addrs = append(addrs, flag.Arg(1))
	} else if len(splitted) == 2 {
		addr, known := ctx.Neigh[*node.Id].Addrs[splitted[1]]
		if !known {
			log.Fatalln("Unknown ADDR specified")
		}
		addrs = append(addrs, addr)
	} else {
		for _, addr := range ctx.Neigh[*node.Id].Addrs {
			addrs = append(addrs, addr)
		}
	}

	var onlyPkts map[[32]byte]bool
	if len(*onlyPktsRaw) > 0 {
		splitted = strings.Split(*onlyPktsRaw, ",")
		onlyPkts = make(map[[32]byte]bool, len(splitted))
		for _, pktIdRaw := range splitted {
			pktId, err := nncp.FromBase32(pktIdRaw)
			if err != nil {
				log.Fatalln("Invalid packet specified: ", err)
			}
			pktIdArr := new([32]byte)
			copy(pktIdArr[:], pktId)
			onlyPkts[*pktIdArr] = true
		}
	}

	if !ctx.CallNode(
		node,
		addrs,
		nice,
		xxOnly,
		*rxRate,
		*txRate,
		*onlineDeadline,
		*maxOnlineTime,
		*listOnly,
		onlyPkts,
	) {
		os.Exit(1)
	}
}
