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

// Call NNCP TCP daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"go.cypherpunks.ru/nncp/v8"
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
		ucspi       = flag.Bool("ucspi", false, "Is it started as UCSPI-TCP client")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		rxOnly      = flag.Bool("rx", false, "Only receive packets")
		txOnly      = flag.Bool("tx", false, "Only transmit packets")
		listOnly    = flag.Bool("list", false, "Only list remote packets")
		noCK        = flag.Bool("nock", false, "Do no checksum checking")
		onlyPktsRaw = flag.String("pkts", "", "Recieve only that packets, comma separated")
		mcdWait     = flag.Uint("mcd-wait", 0, "Wait for MCD for specified number of seconds")
		rxRate      = flag.Int("rxrate", 0, "Maximal receive rate, pkts/sec")
		txRate      = flag.Int("txrate", 0, "Maximal transmit rate, pkts/sec")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
		quiet       = flag.Bool("quiet", false, "Print only errors")
		showPrgrs   = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs   = flag.Bool("noprogress", false, "Omit progress showing")
		debug       = flag.Bool("debug", false, "Print debug messages")
		version     = flag.Bool("version", false, "Print version information")
		warranty    = flag.Bool("warranty", false, "Print warranty information")

		onlineDeadlineSec = flag.Uint("onlinedeadline", 0, "Override onlinedeadline option")
		maxOnlineTimeSec  = flag.Uint("maxonlinetime", 0, "Override maxonlinetime option")

		autoToss       = flag.Bool("autotoss", false, "Toss after call is finished")
		autoTossDoSeen = flag.Bool("autotoss-seen", false, "Create seen/ files during tossing")
		autoTossNoFile = flag.Bool("autotoss-nofile", false, "Do not process \"file\" packets during tossing")
		autoTossNoFreq = flag.Bool("autotoss-nofreq", false, "Do not process \"freq\" packets during tossing")
		autoTossNoExec = flag.Bool("autotoss-noexec", false, "Do not process \"exec\" packets during tossing")
		autoTossNoTrns = flag.Bool("autotoss-notrns", false, "Do not process \"trns\" packets during tossing")
		autoTossNoArea = flag.Bool("autotoss-noarea", false, "Do not process \"area\" packets during tossing")
		autoTossNoACK  = flag.Bool("autotoss-noack", false, "Do not process \"ack\" packets during tossing")
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

	splitted := strings.SplitN(flag.Arg(0), ":", 2)
	node, err := ctx.FindNode(splitted[0])
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}
	if node.NoisePub == nil {
		log.Fatalln("Node does not have online communication capability")
	}

	onlineDeadline := node.OnlineDeadline
	if *onlineDeadlineSec != 0 {
		onlineDeadline = time.Duration(*onlineDeadlineSec) * time.Second
	}
	maxOnlineTime := node.MaxOnlineTime
	if *maxOnlineTimeSec != 0 {
		maxOnlineTime = time.Duration(*maxOnlineTimeSec) * time.Second
	}

	var xxOnly nncp.TRxTx
	if *rxOnly {
		xxOnly = nncp.TRx
	} else if *txOnly {
		xxOnly = nncp.TTx
	}

	var addrs []string
	if *ucspi {
		addrs = append(addrs, nncp.UCSPITCPClient)
	} else if flag.NArg() == 2 {
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

	if *mcdWait > 0 {
		ifis, err := net.Interfaces()
		if err != nil {
			log.Fatalln("Can not get network interfaces list:", err)
		}
		for _, ifiReString := range ctx.MCDRxIfis {
			ifiRe, err := regexp.CompilePOSIX(ifiReString)
			if err != nil {
				log.Fatalf("Can not compile POSIX regexp \"%s\": %s", ifiReString, err)
			}
			for _, ifi := range ifis {
				if ifiRe.MatchString(ifi.Name) {
					if err = ctx.MCDRx(ifi.Name); err != nil {
						log.Printf("Can not run MCD reception on %s: %s", ifi.Name, err)
					}
				}
			}
		}
		addrs = nil
		for i := int(*mcdWait); i > 0; i-- {
			nncp.MCDAddrsM.RLock()
			for _, mcdAddr := range nncp.MCDAddrs[*node.Id] {
				addrs = append(addrs, mcdAddr.Addr.String())
			}
			if len(addrs) > 0 {
				break
			}
			nncp.MCDAddrsM.RUnlock()
			time.Sleep(time.Second)
		}
		if len(addrs) == 0 {
			log.Fatalf("No MCD packets from the node during %d seconds", *mcdWait)
		}
	}

	var onlyPkts map[[32]byte]bool
	if len(*onlyPktsRaw) > 0 {
		splitted = strings.Split(*onlyPktsRaw, ",")
		onlyPkts = make(map[[32]byte]bool, len(splitted))
		for _, pktIdRaw := range splitted {
			pktId, err := nncp.Base32Codec.DecodeString(pktIdRaw)
			if err != nil {
				log.Fatalln("Invalid packet specified: ", err)
			}
			pktIdArr := new([32]byte)
			copy(pktIdArr[:], pktId)
			onlyPkts[*pktIdArr] = true
		}
	}

	ctx.Umask()

	var autoTossFinish chan struct{}
	var autoTossBadCode chan bool
	if *autoToss {
		autoTossFinish, autoTossBadCode = ctx.AutoToss(
			node.Id,
			nice,
			*autoTossDoSeen,
			*autoTossNoFile,
			*autoTossNoFreq,
			*autoTossNoExec,
			*autoTossNoTrns,
			*autoTossNoArea,
			*autoTossNoACK,
		)
	}

	badCode := !ctx.CallNode(
		node,
		addrs,
		nice,
		xxOnly,
		*rxRate,
		*txRate,
		onlineDeadline,
		maxOnlineTime,
		*listOnly,
		*noCK,
		onlyPkts,
	)

	if *autoToss {
		close(autoTossFinish)
		badCode = (<-autoTossBadCode) || badCode
	}
	nncp.SPCheckerWg.Wait()
	if badCode {
		os.Exit(1)
	}
}
