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

// Croned NNCP TCP daemon caller.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-caller -- croned NNCP TCP daemon caller\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [NODE ...]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")

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

	var nodes []*nncp.Node
	if flag.NArg() > 0 {
		for _, nodeId := range flag.Args() {
			node, err := ctx.FindNode(nodeId)
			if err != nil {
				log.Fatalln("Invalid NODE specified:", err)
			}
			if node.NoisePub == nil {
				log.Fatalln("Node", nodeId, "does not have online communication capability")
			}
			if len(node.Calls) == 0 {
				ctx.LogD(
					"caller-no-calls",
					nncp.LEs{{K: "Node", V: node.Id}},
					func(les nncp.LEs) string {
						return fmt.Sprintf("%s node has no calls, skipping", node.Name)
					},
				)
				continue
			}
			nodes = append(nodes, node)
		}
	} else {
		for _, node := range ctx.Neigh {
			if len(node.Calls) == 0 {
				ctx.LogD(
					"caller-no-calls",
					nncp.LEs{{K: "Node", V: node.Id}},
					func(les nncp.LEs) string {
						return fmt.Sprintf("%s node has no calls, skipping", node.Name)
					},
				)
				continue
			}
			nodes = append(nodes, node)
		}
	}

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

	var wg sync.WaitGroup
	for _, node := range nodes {
		for i, call := range node.Calls {
			wg.Add(1)
			go func(node *nncp.Node, i int, call *nncp.Call) {
				defer wg.Done()
				var addrsFromCfg []string
				if call.Addr == nil {
					for _, addr := range node.Addrs {
						addrsFromCfg = append(addrsFromCfg, addr)
					}
				} else {
					addrsFromCfg = append(addrsFromCfg, *call.Addr)
				}
				les := nncp.LEs{{K: "Node", V: node.Id}, {K: "CallIndex", V: i}}
				logMsg := func(les nncp.LEs) string {
					return fmt.Sprintf("%s node, call %d", node.Name, i)
				}
				for {
					n := time.Now()
					t := call.Cron.Next(n)
					ctx.LogD("caller-time", les, func(les nncp.LEs) string {
						return logMsg(les) + ": " + t.String()
					})
					if t.IsZero() {
						ctx.LogE("caller", les, errors.New("got zero time"), logMsg)
						return
					}
					time.Sleep(t.Sub(n))
					node.Lock()
					if node.Busy {
						node.Unlock()
						ctx.LogD("caller-busy", les, func(les nncp.LEs) string {
							return logMsg(les) + ": busy"
						})
						continue
					} else {
						node.Busy = true
						node.Unlock()

						if call.WhenTxExists && call.Xx != "TRx" {
							ctx.LogD("caller", les, func(les nncp.LEs) string {
								return logMsg(les) + ": checking tx existence"
							})
							txExists := false
							for job := range ctx.Jobs(node.Id, nncp.TTx) {
								if job.PktEnc.Nice > call.Nice {
									continue
								}
								txExists = true
							}
							if !txExists {
								ctx.LogD("caller-no-tx", les, func(les nncp.LEs) string {
									return logMsg(les) + ": no tx"
								})
								node.Lock()
								node.Busy = false
								node.Unlock()
								continue
							}
						}

						var autoTossFinish chan struct{}
						var autoTossBadCode chan bool
						if call.AutoToss || *autoToss {
							autoTossFinish, autoTossBadCode = ctx.AutoToss(
								node.Id,
								call.Nice,
								call.AutoTossDoSeen || *autoTossDoSeen,
								call.AutoTossNoFile || *autoTossNoFile,
								call.AutoTossNoFreq || *autoTossNoFreq,
								call.AutoTossNoExec || *autoTossNoExec,
								call.AutoTossNoTrns || *autoTossNoTrns,
								call.AutoTossNoArea || *autoTossNoArea,
								call.AutoTossNoACK || *autoTossNoACK,
							)
						}

						var addrs []string
						if !call.MCDIgnore {
							nncp.MCDAddrsM.RLock()
							for _, mcdAddr := range nncp.MCDAddrs[*node.Id] {
								ctx.LogD("caller", les, func(les nncp.LEs) string {
									return logMsg(les) + ": adding MCD address: " +
										mcdAddr.Addr.String()
								})
								addrs = append(addrs, mcdAddr.Addr.String())
							}
							nncp.MCDAddrsM.RUnlock()
						}

						ctx.CallNode(
							node,
							append(addrs, addrsFromCfg...),
							call.Nice,
							call.Xx,
							call.RxRate,
							call.TxRate,
							call.OnlineDeadline,
							call.MaxOnlineTime,
							false,
							call.NoCK,
							nil,
						)

						if call.AutoToss || *autoToss {
							close(autoTossFinish)
							<-autoTossBadCode
						}

						node.Lock()
						node.Busy = false
						node.Unlock()
					}
				}
			}(node, i, call)
		}
	}
	wg.Wait()
	nncp.SPCheckerWg.Wait()
}
