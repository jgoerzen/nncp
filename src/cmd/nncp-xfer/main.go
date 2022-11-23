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

// Exchange NNCP inbound and outbounds packets with external directory.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-xfer -- copy inbound and outbounds packets\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] DIR\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		rxOnly    = flag.Bool("rx", false, "Only receive packets")
		txOnly    = flag.Bool("tx", false, "Only transfer packets")
		mkdir     = flag.Bool("mkdir", false, "Create necessary outbound directories")
		keep      = flag.Bool("keep", false, "Do not delete transferred packets")
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
	if flag.NArg() != 1 {
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

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

	ctx.Umask()
	selfPath := filepath.Join(flag.Arg(0), ctx.SelfId.String())
	isBad := false
	var dir *os.File
	var fis []os.FileInfo
	var les nncp.LEs
	var logMsg func(les nncp.LEs) string
	if *txOnly {
		goto Tx
	}
	les = nncp.LEs{
		{K: "XX", V: string(nncp.TRx)},
		{K: "Dir", V: selfPath},
	}
	logMsg = func(les nncp.LEs) string {
		return "Packet transfer, received from self"
	}
	ctx.LogD("xfer-self", les, logMsg)
	if _, err = os.Stat(selfPath); err != nil {
		if os.IsNotExist(err) {
			ctx.LogD("xfer-self-no-dir", les, func(les nncp.LEs) string {
				return logMsg(les) + ": no directory"
			})
			goto Tx
		}
		ctx.LogE("xfer-self-stat", les, err, func(les nncp.LEs) string {
			return logMsg(les) + ": stating"
		})
		isBad = true
		goto Tx
	}
	dir, err = os.Open(selfPath)
	if err != nil {
		ctx.LogE("xfer-self-open", les, err, func(les nncp.LEs) string {
			return logMsg(les) + ": opening"
		})
		isBad = true
		goto Tx
	}
	fis, err = dir.Readdir(0)
	dir.Close()
	if err != nil {
		ctx.LogE("xfer-self-read", les, err, func(les nncp.LEs) string {
			return logMsg(les) + ": reading"
		})
		isBad = true
		goto Tx
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		nodeId, err := nncp.NodeIdFromString(fi.Name())
		les := append(les, nncp.LE{K: "Node", V: fi.Name()})
		logMsg := func(les nncp.LEs) string {
			return "Packet transfer, received from " + ctx.NodeName(nodeId)
		}
		if err != nil {
			ctx.LogD("xfer-rx-not-node", les, func(les nncp.LEs) string {
				return logMsg(les) + ": is not NodeId"
			})
			continue
		}
		if nodeOnly != nil && *nodeId != *nodeOnly.Id {
			ctx.LogD("xfer-rx-skip", les, func(les nncp.LEs) string {
				return logMsg(les) + ": skipping"
			})
			continue
		}
		if _, known := ctx.Neigh[*nodeId]; !known {
			ctx.LogD("xfer-rx-unknown", les, func(les nncp.LEs) string {
				return logMsg(les) + ": unknown"
			})
			continue
		}
		dir, err = os.Open(filepath.Join(selfPath, fi.Name()))
		if err != nil {
			ctx.LogE("xfer-rx-open", les, err, func(les nncp.LEs) string {
				return logMsg(les) + ": opening"
			})
			isBad = true
			continue
		}
		fisInt, err := dir.Readdir(0)
		dir.Close()
		if err != nil {
			ctx.LogE("xfer-rx-read", les, err, func(les nncp.LEs) string {
				return logMsg(les) + ": reading"
			})
			isBad = true
			continue
		}
		for _, fiInt := range fisInt {
			if !fi.IsDir() {
				continue
			}
			// Check that it is valid Base32 encoding
			if _, err = nncp.NodeIdFromString(fiInt.Name()); err != nil {
				continue
			}
			filename := filepath.Join(dir.Name(), fiInt.Name())
			les := append(les, nncp.LE{K: "File", V: filename})
			logMsg := func(les nncp.LEs) string {
				return fmt.Sprintf(
					"Packet transfer, received from %s: %s",
					ctx.NodeName(nodeId), filename,
				)
			}
			if _, err = os.Stat(filepath.Join(
				ctx.Spool,
				nodeId.String(),
				string(nncp.TRx),
				nncp.SeenDir,
				fiInt.Name(),
			)); err == nil || !os.IsNotExist(err) {
				ctx.LogI("xfer-rx-seen", les, func(les nncp.LEs) string {
					return logMsg(les) + ": packet already seen"
				})
				if !*keep {
					if err = os.Remove(filename); err != nil {
						ctx.LogE("xfer-rx-remove", les, err, logMsg)
						isBad = true
					}
				}
				continue
			}
			fd, err := os.Open(filename)
			if err != nil {
				ctx.LogE("xfer-rx-open", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": opening"
				})
				isBad = true
				continue
			}
			pktEnc, pktEncRaw, err := ctx.HdrRead(fd)
			if err == nil {
				switch pktEnc.Magic {
				case nncp.MagicNNCPEv1.B:
					err = nncp.MagicNNCPEv1.TooOld()
				case nncp.MagicNNCPEv2.B:
					err = nncp.MagicNNCPEv2.TooOld()
				case nncp.MagicNNCPEv3.B:
					err = nncp.MagicNNCPEv3.TooOld()
				case nncp.MagicNNCPEv4.B:
					err = nncp.MagicNNCPEv4.TooOld()
				case nncp.MagicNNCPEv5.B:
					err = nncp.MagicNNCPEv5.TooOld()
				case nncp.MagicNNCPEv6.B:
				default:
					err = errors.New("is not an encrypted packet")
				}
			}
			if err != nil {
				ctx.LogD(
					"xfer-rx-not-packet",
					append(les, nncp.LE{K: "Err", V: err}),
					func(les nncp.LEs) string {
						return logMsg(les) + ": not valid packet: " + err.Error()
					},
				)
				fd.Close()
				continue
			}
			if pktEnc.Nice > nice {
				ctx.LogD("xfer-rx-too-nice", les, func(les nncp.LEs) string {
					return logMsg(les) + ": too nice"
				})
				fd.Close()
				continue
			}
			les = append(les, nncp.LE{K: "Size", V: fiInt.Size()})
			logMsg = func(les nncp.LEs) string {
				return fmt.Sprintf(
					"Packet transfer, received from %s: %s (%s)",
					ctx.NodeName(nodeId), filename,
					humanize.IBytes(uint64(fiInt.Size())),
				)
			}
			if !ctx.IsEnoughSpace(fiInt.Size()) {
				ctx.LogE("xfer-rx", les, errors.New("is not enough space"), logMsg)
				fd.Close()
				continue
			}
			if _, err = fd.Seek(0, io.SeekStart); err != nil {
				log.Fatalln(err)
			}
			tmp, err := ctx.NewTmpFileWHash()
			if err != nil {
				log.Fatalln(err)
			}
			r, w := io.Pipe()
			go func() {
				_, err := io.CopyN(
					w, bufio.NewReaderSize(fd, nncp.MTHBlockSize), fiInt.Size(),
				)
				if err == nil {
					err = w.Close()
				}
				if err != nil {
					ctx.LogE("xfer-rx", les, err, logMsg)
					w.CloseWithError(err)
				}
			}()
			_, err = nncp.CopyProgressed(
				tmp.W, r, "Rx",
				append(
					les,
					nncp.LE{K: "Pkt", V: filename},
					nncp.LE{K: "FullSize", V: fiInt.Size()},
				),
				ctx.ShowPrgrs,
			)
			fd.Close()
			if err != nil {
				ctx.LogE("xfer-rx", les, err, logMsg)
				tmp.Cancel()
				isBad = true
				continue
			}
			if err = tmp.W.Flush(); err != nil {
				ctx.LogE("xfer-rx", les, err, logMsg)
				tmp.Cancel()
				isBad = true
				continue
			}
			if tmp.Checksum() != fiInt.Name() {
				ctx.LogE("xfer-rx", les, errors.New("checksum mismatch"), logMsg)
				tmp.Cancel()
				isBad = true
				continue
			}
			if err = tmp.Commit(filepath.Join(
				ctx.Spool,
				nodeId.String(),
				string(nncp.TRx),
			)); err != nil {
				log.Fatalln(err)
			}
			ctx.LogI("xfer-rx", les, logMsg)
			if !*keep {
				if err = os.Remove(filename); err != nil {
					ctx.LogE("xfer-rx-remove", les, err, logMsg)
					isBad = true
				}
			}
			if ctx.HdrUsage {
				ctx.HdrWrite(pktEncRaw, filepath.Join(
					ctx.Spool,
					nodeId.String(),
					string(nncp.TRx),
					tmp.Checksum(),
				))
			}
		}
	}

Tx:
	if *rxOnly {
		if isBad {
			os.Exit(1)
		}
		return
	}
	for nodeId := range ctx.Neigh {
		les := nncp.LEs{{K: "XX", V: string(nncp.TTx)}, {K: "Node", V: nodeId}}
		logMsg := func(les nncp.LEs) string {
			return "Packet transfer, sent to " + ctx.NodeName(&nodeId)
		}
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			ctx.LogD("xfer-tx-skip", les, func(les nncp.LEs) string {
				return logMsg(les) + ": skipping"
			})
			continue
		}
		dirLock, err := ctx.LockDir(&nodeId, string(nncp.TTx))
		if err != nil {
			continue
		}
		nodePath := filepath.Join(flag.Arg(0), nodeId.String())
		les = append(les, nncp.LE{K: "Dir", V: nodePath})
		logMsg = func(les nncp.LEs) string {
			return fmt.Sprintf(
				"Packet transfer, sent to %s: directory %s",
				ctx.NodeName(&nodeId), nodePath,
			)
		}
		_, err = os.Stat(nodePath)
		if err != nil {
			if os.IsNotExist(err) {
				ctx.LogD("xfer-tx-not-exist", les, func(les nncp.LEs) string {
					return logMsg(les) + ": does not exist"
				})
				if !*mkdir {
					ctx.UnlockDir(dirLock)
					continue
				}
				if err = os.Mkdir(nodePath, os.FileMode(0777)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("xfer-tx-mkdir", les, err, logMsg)
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("xfer-tx", les, err, logMsg)
				isBad = true
				continue
			}
		}
		dstPath := filepath.Join(nodePath, ctx.SelfId.String())
		les[len(les)-1].V = dstPath
		logMsg = func(les nncp.LEs) string {
			return fmt.Sprintf(
				"Packet transfer, sent to %s: directory %s",
				ctx.NodeName(&nodeId), dstPath,
			)
		}
		_, err = os.Stat(dstPath)
		if err != nil {
			if os.IsNotExist(err) {
				if err = os.Mkdir(dstPath, os.FileMode(0777)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("xfer-tx-mkdir", les, err, logMsg)
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("xfer-tx", les, err, logMsg)
				isBad = true
				continue
			}
		}
		les = les[:len(les)-1]
		for job := range ctx.Jobs(&nodeId, nncp.TTx) {
			pktName := filepath.Base(job.Path)
			les := append(les, nncp.LE{K: "Pkt", V: pktName})
			logMsg = func(les nncp.LEs) string {
				return fmt.Sprintf(
					"Packet transfer, sent to %s: %s",
					ctx.NodeName(&nodeId), pktName,
				)
			}
			if job.PktEnc.Nice > nice {
				ctx.LogD("xfer-tx-too-nice", les, func(les nncp.LEs) string {
					return logMsg(les) + ": too nice"
				})
				continue
			}
			if _, err = os.Stat(filepath.Join(dstPath, pktName)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("xfer-tx-exists", les, func(les nncp.LEs) string {
					return logMsg(les) + ": already exists"
				})
				continue
			}
			tmp, err := nncp.TempFile(dstPath, "xfer")
			if err != nil {
				ctx.LogE("xfer-tx-mktemp", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": mktemp"
				})
				isBad = true
				break
			}
			les = append(les, nncp.LE{K: "Tmp", V: tmp.Name()})
			ctx.LogD("xfer-tx-tmp-create", les, func(les nncp.LEs) string {
				return fmt.Sprintf("%s: temporary %s created", logMsg(les), tmp.Name())
			})
			fd, err := os.Open(job.Path)
			if err != nil {
				ctx.LogE("xfer-tx-open", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": opening"
				})
				tmp.Close()
				isBad = true
				continue
			}
			bufW := bufio.NewWriter(tmp)
			copied, err := nncp.CopyProgressed(
				bufW, bufio.NewReaderSize(fd, nncp.MTHBlockSize), "Tx",
				append(les, nncp.LE{K: "FullSize", V: job.Size}),
				ctx.ShowPrgrs,
			)
			fd.Close()
			if err != nil {
				ctx.LogE("xfer-tx-copy", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": copying"
				})
				tmp.Close()
				isBad = true
				continue
			}
			if err = bufW.Flush(); err != nil {
				tmp.Close()
				ctx.LogE("xfer-tx-flush", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": flushing"
				})
				isBad = true
				continue
			}
			if !nncp.NoSync {
				if err = tmp.Sync(); err != nil {
					tmp.Close()
					ctx.LogE("xfer-tx-sync", les, err, func(les nncp.LEs) string {
						return logMsg(les) + ": syncing"
					})
					isBad = true
					continue
				}
			}
			if err = tmp.Close(); err != nil {
				ctx.LogE("xfer-tx-close", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": closing"
				})
			}
			if err = os.Rename(tmp.Name(), filepath.Join(dstPath, pktName)); err != nil {
				ctx.LogE("xfer-tx-rename", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": renaming"
				})
				isBad = true
				continue
			}
			if err = nncp.DirSync(dstPath); err != nil {
				ctx.LogE("xfer-tx-dirsync", les, err, func(les nncp.LEs) string {
					return logMsg(les) + ": dirsyncing"
				})
				isBad = true
				continue
			}
			os.Remove(filepath.Join(dstPath, pktName+".part"))
			les = les[:len(les)-1]
			ctx.LogI(
				"xfer-tx",
				append(les, nncp.LE{K: "Size", V: copied}),
				func(les nncp.LEs) string {
					return fmt.Sprintf(
						"%s (%s)", logMsg(les), humanize.IBytes(uint64(copied)),
					)
				},
			)
			if !*keep {
				if err = os.Remove(job.Path); err != nil {
					ctx.LogE("xfer-tx-remove", les, err, func(les nncp.LEs) string {
						return logMsg(les) + ": removing"
					})
					isBad = true
				} else if ctx.HdrUsage {
					os.Remove(nncp.JobPath2Hdr(job.Path))
				}
			}
		}
		ctx.UnlockDir(dirLock)
	}
	if isBad {
		os.Exit(1)
	}
}
