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

// Remove packet from the queue.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-rm -- remove packet\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [-older X] -tmp\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -lock\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} -part\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} -seen\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} -nock\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} -area\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} {-rx|-tx} [-hdr]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] [-older X] {-all|-node NODE} -pkt < ...\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "-older option's time units are: (s)econds, (m)inutes, (h)ours, (d)ays")
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		doTmp     = flag.Bool("tmp", false, "Remove temporary files")
		doLock    = flag.Bool("lock", false, "Remove all lock files")
		doAll     = flag.Bool("all", false, "Process all nodes")
		nodeRaw   = flag.String("node", "", "Process only that node")
		doRx      = flag.Bool("rx", false, "Process inbound packets")
		doTx      = flag.Bool("tx", false, "Process outbound packets")
		doPart    = flag.Bool("part", false, "Remove only .part files")
		doSeen    = flag.Bool("seen", false, "Remove only seen/ files")
		doNoCK    = flag.Bool("nock", false, "Remove only .nock files")
		doHdr     = flag.Bool("hdr", false, "Remove only hdr/ files")
		doArea    = flag.Bool("area", false, "Remove only area/* seen files")
		older     = flag.String("older", "", "XXX{smhd}: only older than XXX number of time units")
		dryRun    = flag.Bool("dryrun", false, "Do not actually remove files")
		doPkt     = flag.Bool("pkt", false, "Remove only that packets")
		spoolPath = flag.String("spool", "", "Override path to spool")
		quiet     = flag.Bool("quiet", false, "Print only errors")
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, "", *quiet, false, false, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	ctx.Umask()

	var oldBoundaryRaw int
	if *older != "" {
		olderRe := regexp.MustCompile(`^(\d+)([smhd])$`)
		matches := olderRe.FindStringSubmatch(*older)
		if len(matches) != 1+2 {
			log.Fatalln("can not parse -older")
		}
		oldBoundaryRaw, err = strconv.Atoi(matches[1])
		if err != nil {
			log.Fatalln("can not parse -older:", err)
		}
		switch matches[2] {
		case "s":
			break
		case "m":
			oldBoundaryRaw *= 60
		case "h":
			oldBoundaryRaw *= 60 * 60
		case "d":
			oldBoundaryRaw *= 60 * 60 * 24
		}
	}
	oldBoundary := time.Second * time.Duration(oldBoundaryRaw)

	pkts := make(map[string]struct{})
	if *doPkt {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln("can not read -pkt from stdin:", err)
		}
		for _, line := range strings.Fields(string(raw)) {
			if len(line) == 0 {
				continue
			}
			cols := strings.Split(line, "/")
			pkts[cols[len(cols)-1]] = struct{}{}
		}
	}

	now := time.Now()
	if *doTmp {
		err = filepath.Walk(
			filepath.Join(ctx.Spool, "tmp"),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				if now.Sub(info.ModTime()) < oldBoundary {
					ctx.LogD("rm-skip", nncp.LEs{{K: "File", V: path}}, func(les nncp.LEs) string {
						return fmt.Sprintf("File %s: too fresh, skipping", path)
					})
					return nil
				}
				ctx.LogI("rm", nncp.LEs{{K: "File", V: path}}, func(les nncp.LEs) string {
					return fmt.Sprintf("File %s: removed", path)
				})
				if *dryRun {
					return nil
				}
				return os.Remove(path)
			})
		if err != nil {
			log.Fatalln("Error during walking:", err)
		}
		return
	}

	if *doLock {
		err = filepath.Walk(ctx.Spool, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if strings.HasSuffix(info.Name(), ".lock") {
				ctx.LogI("rm", nncp.LEs{{K: "File", V: path}}, func(les nncp.LEs) string {
					return fmt.Sprintf("File %s: removed", path)
				})
				if *dryRun {
					return nil
				}
				return os.Remove(path)
			}
			return nil
		})
		if err != nil {
			log.Fatalln("Error during walking:", err)
		}
		return
	}

	var nodeId *nncp.NodeId
	if *nodeRaw == "" {
		if !*doAll {
			usage()
			os.Exit(1)
		}
	} else {
		node, err := ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
		nodeId = node.Id
	}

	for _, node := range ctx.Neigh {
		if nodeId != nil && node.Id != nodeId {
			continue
		}
		remove := func(xx nncp.TRxTx) error {
			p := filepath.Join(ctx.Spool, node.Id.String(), string(xx))
			if _, err := os.Stat(p); err != nil && os.IsNotExist(err) {
				return nil
			}
			dir, err := os.Open(p)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			defer dir.Close()
			for {
				entries, err := dir.ReadDir(1 << 10)
				if err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					pth := filepath.Join(p, entry.Name())
					logMsg := func(les nncp.LEs) string {
						return fmt.Sprintf("File %s: removed", pth)
					}
					if len(pkts) > 0 {
						if _, exists := pkts[filepath.Base(entry.Name())]; exists {
							ctx.LogI("rm", nncp.LEs{{K: "File", V: pth}}, logMsg)
							if !*dryRun {
								os.Remove(nncp.JobPath2Hdr(pth))
								if err = os.Remove(pth); err != nil {
									return err
								}
							}
						}
						continue
					}
					info, err := entry.Info()
					if err != nil {
						return err
					}
					if now.Sub(info.ModTime()) < oldBoundary {
						ctx.LogD("rm-skip", nncp.LEs{{K: "File", V: pth}}, func(les nncp.LEs) string {
							return fmt.Sprintf("File %s: too fresh, skipping", pth)
						})
						continue
					}
					if (*doNoCK && strings.HasSuffix(entry.Name(), nncp.NoCKSuffix)) ||
						(*doPart && strings.HasSuffix(entry.Name(), nncp.PartSuffix)) {
						ctx.LogI("rm", nncp.LEs{{K: "File", V: pth}}, logMsg)
						if *dryRun {
							continue
						}
						if err = os.Remove(pth); err != nil {
							return err
						}
					}
					if !*doSeen && !*doNoCK && !*doHdr && !*doPart &&
						(*doRx || *doTx) &&
						((*doRx && xx == nncp.TRx) || (*doTx && xx == nncp.TTx)) {
						ctx.LogI("rm", nncp.LEs{{K: "File", V: pth}}, logMsg)
						if *dryRun {
							continue
						}
						os.Remove(nncp.JobPath2Hdr(pth))
						if err = os.Remove(pth); err != nil {
							return err
						}
					}
				}
			}
			return nil
		}
		if len(pkts) > 0 || *doRx || *doNoCK || *doPart {
			if err = remove(nncp.TRx); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
		if len(pkts) > 0 || *doTx {
			if err = remove(nncp.TTx); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
		removeSub := func(p string) error {
			return filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					if os.IsNotExist(err) {
						return nil
					}
					return err
				}
				if info.IsDir() {
					return nil
				}
				logMsg := func(les nncp.LEs) string {
					return fmt.Sprintf("File %s: removed", path)
				}
				if len(pkts) > 0 {
					if _, exists := pkts[filepath.Base(info.Name())]; !exists {
						return nil
					}
					ctx.LogI("rm", nncp.LEs{{K: "File", V: path}}, logMsg)
					if *dryRun {
						return nil
					}
					return os.Remove(path)
				}
				if now.Sub(info.ModTime()) < oldBoundary {
					ctx.LogD(
						"rm-skip", nncp.LEs{{K: "File", V: path}},
						func(les nncp.LEs) string {
							return fmt.Sprintf("File %s: too fresh, skipping", path)
						},
					)
					return nil
				}
				ctx.LogI("rm", nncp.LEs{{K: "File", V: path}}, logMsg)
				if *dryRun {
					return nil
				}
				return os.Remove(path)
			})
		}
		if len(pkts) > 0 || *doSeen {
			if err = removeSub(filepath.Join(
				ctx.Spool, node.Id.String(), string(nncp.TRx), nncp.SeenDir,
			)); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
		if *doRx && *doHdr {
			if err = removeSub(filepath.Join(
				ctx.Spool, node.Id.String(), string(nncp.TRx), nncp.HdrDir,
			)); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
		if *doTx && *doHdr {
			if err = removeSub(filepath.Join(
				ctx.Spool, node.Id.String(), string(nncp.TTx), nncp.HdrDir,
			)); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
		if *doArea {
			if err = filepath.Walk(
				filepath.Join(ctx.Spool, node.Id.String(), nncp.AreaDir),
				func(path string, info os.FileInfo, err error) error {
					if err != nil {
						if os.IsNotExist(err) {
							return nil
						}
						return err
					}
					if info.IsDir() {
						return nil
					}
					if now.Sub(info.ModTime()) < oldBoundary {
						ctx.LogD(
							"rm-skip", nncp.LEs{{K: "File", V: path}},
							func(les nncp.LEs) string {
								return fmt.Sprintf("File %s: too fresh, skipping", path)
							},
						)
						return nil
					}
					ctx.LogI(
						"rm",
						nncp.LEs{{K: "File", V: path}},
						func(les nncp.LEs) string {
							return fmt.Sprintf("File %s: removed", path)
						},
					)
					if *dryRun {
						return nil
					}
					return os.Remove(path)
				}); err != nil {
				log.Fatalln("Can not remove:", err)
			}
		}
	}
}
