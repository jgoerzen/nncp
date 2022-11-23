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

// Create/digest stream of NNCP encrypted packets.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-bundle -- Create/digest stream of NNCP encrypted packets\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -tx [-delete] NODE [NODE ...] > ...\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -rx -delete [-dryrun] [NODE ...] < ...\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -rx [-check] [-dryrun] [NODE ...] < ...\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		doRx      = flag.Bool("rx", false, "Receive packets")
		doTx      = flag.Bool("tx", false, "Transfer packets")
		doDelete  = flag.Bool("delete", false, "Delete transferred packets")
		doCheck   = flag.Bool("check", false, "Check integrity while receiving")
		dryRun    = flag.Bool("dryrun", false, "Do no writes")
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
	if *doRx && *doTx {
		log.Fatalln("-rx and -tx can not be set simultaneously")
	}
	if !*doRx && !*doTx {
		log.Fatalln("At least one of -rx and -tx must be specified")
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

	nodeIds := make(map[nncp.NodeId]struct{}, flag.NArg())
	for i := 0; i < flag.NArg(); i++ {
		node, err := ctx.FindNode(flag.Arg(i))
		if err != nil {
			log.Fatalln("Invalid node specified:", err)
		}
		nodeIds[*node.Id] = struct{}{}
	}

	ctx.Umask()

	if *doTx {
		var pktName string
		bufStdout := bufio.NewWriter(os.Stdout)
		tarWr := tar.NewWriter(bufStdout)
		for nodeId := range nodeIds {
			for job := range ctx.Jobs(&nodeId, nncp.TTx) {
				pktName = filepath.Base(job.Path)
				les := nncp.LEs{
					{K: "XX", V: string(nncp.TTx)},
					{K: "Node", V: nodeId.String()},
					{K: "Pkt", V: pktName},
				}
				if job.PktEnc.Nice > nice {
					ctx.LogD("bundle-tx-too-nice", les, func(les nncp.LEs) string {
						return fmt.Sprintf(
							"Bundle transfer %s/tx/%s: too nice %s",
							ctx.NodeName(&nodeId),
							pktName,
							nncp.NicenessFmt(job.PktEnc.Nice),
						)
					})
					continue
				}
				fd, err := os.Open(job.Path)
				if err != nil {
					log.Fatalln("Error during opening:", err)
				}
				if err = tarWr.WriteHeader(&tar.Header{
					Format:   tar.FormatUSTAR,
					Name:     nncp.NNCPBundlePrefix,
					Mode:     0700,
					Typeflag: tar.TypeDir,
				}); err != nil {
					log.Fatalln("Error writing tar header:", err)
				}
				if err = tarWr.WriteHeader(&tar.Header{
					Format: tar.FormatPAX,
					Name: strings.Join([]string{
						nncp.NNCPBundlePrefix,
						nodeId.String(),
						ctx.SelfId.String(),
						pktName,
					}, "/"),
					Mode:     0400,
					Size:     job.Size,
					Typeflag: tar.TypeReg,
				}); err != nil {
					log.Fatalln("Error writing tar header:", err)
				}
				if _, err = nncp.CopyProgressed(
					tarWr, bufio.NewReaderSize(fd, nncp.MTHBlockSize), "Tx",
					append(les, nncp.LEs{
						{K: "Pkt", V: nncp.Base32Codec.EncodeToString(job.HshValue[:])},
						{K: "FullSize", V: job.Size},
					}...),
					ctx.ShowPrgrs,
				); err != nil {
					log.Fatalln("Error during copying to tar:", err)
				}
				if err = fd.Close(); err != nil {
					log.Fatalln("Error during closing:", err)
				}
				if err = tarWr.Flush(); err != nil {
					log.Fatalln("Error during tar flushing:", err)
				}
				if err = bufStdout.Flush(); err != nil {
					log.Fatalln("Error during stdout flushing:", err)
				}
				if *doDelete {
					if err = os.Remove(job.Path); err != nil {
						log.Fatalln("Error during deletion:", err)
					} else if ctx.HdrUsage {
						os.Remove(nncp.JobPath2Hdr(job.Path))
					}
				}
				ctx.LogI(
					"bundle-tx",
					append(les, nncp.LE{K: "Size", V: job.Size}),
					func(les nncp.LEs) string {
						return fmt.Sprintf(
							"Bundle transfer, sent to node %s %s (%s)",
							ctx.NodeName(&nodeId),
							pktName,
							humanize.IBytes(uint64(job.Size)),
						)
					},
				)
			}
		}
		if err = tarWr.Close(); err != nil {
			log.Fatalln("Error during tar closing:", err)
		}
	} else {
		bufStdin := bufio.NewReaderSize(os.Stdin, nncp.MTHBlockSize*2)
		pktEncBuf := make([]byte, nncp.PktEncOverhead)
		var pktEnc *nncp.PktEnc
		for {
			peeked, err := bufStdin.Peek(nncp.MTHBlockSize)
			if err != nil && err != io.EOF {
				log.Fatalln("Error during reading:", err)
			}
			prefixIdx := bytes.Index(peeked, []byte(nncp.NNCPBundlePrefix))
			if prefixIdx == -1 {
				if err == io.EOF {
					break
				}
				bufStdin.Discard(bufStdin.Buffered() - (len(nncp.NNCPBundlePrefix) - 1))
				continue
			}
			if _, err = bufStdin.Discard(prefixIdx); err != nil {
				panic(err)
			}
			tarR := tar.NewReader(bufStdin)
			entry, err := tarR.Next()
			if err != nil {
				if err != io.EOF {
					ctx.LogD(
						"bundle-rx-read-tar",
						nncp.LEs{{K: "XX", V: string(nncp.TRx)}, {K: "Err", V: err}},
						func(les nncp.LEs) string {
							return "Bundle transfer rx: reading tar"
						},
					)
				}
				continue
			}
			if entry.Typeflag != tar.TypeDir {
				ctx.LogD(
					"bundle-rx-read-tar",
					nncp.LEs{
						{K: "XX", V: string(nncp.TRx)},
						{K: "Err", V: errors.New("expected NNCP/")},
					},
					func(les nncp.LEs) string {
						return "Bundle transfer rx: reading tar"
					},
				)
				continue
			}
			entry, err = tarR.Next()
			if err != nil {
				if err != io.EOF {
					ctx.LogD(
						"bundle-rx-read-tar",
						nncp.LEs{{K: "XX", V: string(nncp.TRx)}, {K: "Err", V: err}},
						func(les nncp.LEs) string {
							return "Bundle transfer rx: reading tar"
						},
					)
				}
				continue
			}
			les := nncp.LEs{{K: "XX", V: string(nncp.TRx)}, {K: "Pkt", V: entry.Name}}
			logMsg := func(les nncp.LEs) string {
				return "Bundle transfer rx/" + entry.Name
			}
			if entry.Size < nncp.PktEncOverhead {
				ctx.LogD("bundle-rx-too-small", les, func(les nncp.LEs) string {
					return logMsg(les) + ": too small packet"
				})
				continue
			}
			if !ctx.IsEnoughSpace(entry.Size) {
				ctx.LogE("bundle-rx", les, errors.New("not enough spool space"), logMsg)
				continue
			}
			pktName := filepath.Base(entry.Name)
			if _, err = nncp.Base32Codec.DecodeString(pktName); err != nil {
				ctx.LogD(
					"bundle-rx",
					append(les, nncp.LE{K: "Err", V: "bad packet name"}),
					logMsg,
				)
				continue
			}
			if _, err = io.ReadFull(tarR, pktEncBuf); err != nil {
				ctx.LogD(
					"bundle-rx",
					append(les, nncp.LE{K: "Err", V: err}),
					logMsg,
				)
				continue
			}
			if _, err = xdr.Unmarshal(bytes.NewReader(pktEncBuf), &pktEnc); err != nil {
				ctx.LogD(
					"bundle-rx",
					append(les, nncp.LE{K: "Err", V: "Bad packet structure"}),
					logMsg,
				)
				continue
			}
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
				err = errors.New("Bad packet magic number")
			}
			if err != nil {
				ctx.LogD(
					"bundle-rx",
					append(les, nncp.LE{K: "Err", V: err.Error()}),
					logMsg,
				)
				continue
			}
			if pktEnc.Nice > nice {
				ctx.LogD("bundle-rx-too-nice", les, func(les nncp.LEs) string {
					return logMsg(les) + ": too nice"
				})
				continue
			}
			if *pktEnc.Sender == *ctx.SelfId && *doDelete {
				if len(nodeIds) > 0 {
					if _, exists := nodeIds[*pktEnc.Recipient]; !exists {
						ctx.LogD("bundle-tx-skip", les, func(les nncp.LEs) string {
							return logMsg(les) + ": recipient is not requested"
						})
						continue
					}
				}
				nodeId32 := nncp.Base32Codec.EncodeToString(pktEnc.Recipient[:])
				les := nncp.LEs{
					{K: "XX", V: string(nncp.TTx)},
					{K: "Node", V: nodeId32},
					{K: "Pkt", V: pktName},
				}
				logMsg = func(les nncp.LEs) string {
					return fmt.Sprintf("Bundle transfer %s/tx/%s", nodeId32, pktName)
				}
				dstPath := filepath.Join(ctx.Spool, nodeId32, string(nncp.TTx), pktName)
				if _, err = os.Stat(dstPath); err != nil {
					ctx.LogD("bundle-tx-missing", les, func(les nncp.LEs) string {
						return logMsg(les) + ": packet is already missing"
					})
					continue
				}
				hsh := nncp.MTHNew(entry.Size, 0)
				if _, err = hsh.Write(pktEncBuf); err != nil {
					log.Fatalln("Error during writing:", err)
				}
				if _, err = nncp.CopyProgressed(
					hsh, tarR, "Rx",
					append(les, nncp.LE{K: "FullSize", V: entry.Size}),
					ctx.ShowPrgrs,
				); err != nil {
					log.Fatalln("Error during copying:", err)
				}
				if nncp.Base32Codec.EncodeToString(hsh.Sum(nil)) == pktName {
					ctx.LogI("bundle-tx-removed", les, func(les nncp.LEs) string {
						return logMsg(les) + ": removed"
					})
					if !*dryRun {
						os.Remove(dstPath)
						if ctx.HdrUsage {
							os.Remove(nncp.JobPath2Hdr(dstPath))
						}
					}
				} else {
					ctx.LogE("bundle-tx", les, errors.New("bad checksum"), logMsg)
				}
				continue
			}
			if *pktEnc.Recipient != *ctx.SelfId {
				ctx.LogD("nncp-bundle", les, func(les nncp.LEs) string {
					return logMsg(les) + ": unknown recipient"
				})
				continue
			}
			if len(nodeIds) > 0 {
				if _, exists := nodeIds[*pktEnc.Sender]; !exists {
					ctx.LogD("bundle-rx-skip", les, func(les nncp.LEs) string {
						return logMsg(les) + ": sender is not requested"
					})
					continue
				}
			}
			sender := nncp.Base32Codec.EncodeToString(pktEnc.Sender[:])
			les = nncp.LEs{
				{K: "XX", V: string(nncp.TRx)},
				{K: "Node", V: sender},
				{K: "Pkt", V: pktName},
				{K: "FullSize", V: entry.Size},
			}
			logMsg = func(les nncp.LEs) string {
				return fmt.Sprintf("Bundle transfer %s/rx/%s", sender, pktName)
			}
			dstDirPath := filepath.Join(ctx.Spool, sender, string(nncp.TRx))
			dstPath := filepath.Join(dstDirPath, pktName)
			if _, err = os.Stat(dstPath); err == nil || !os.IsNotExist(err) {
				ctx.LogD("bundle-rx-exists", les, func(les nncp.LEs) string {
					return logMsg(les) + ": packet already exists"
				})
				continue
			}
			if _, err = os.Stat(filepath.Join(
				dstDirPath, nncp.SeenDir, pktName,
			)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("bundle-rx-seen", les, func(les nncp.LEs) string {
					return logMsg(les) + ": packet already seen"
				})
				continue
			}
			if *doCheck {
				if *dryRun {
					hsh := nncp.MTHNew(entry.Size, 0)
					if _, err = hsh.Write(pktEncBuf); err != nil {
						log.Fatalln("Error during writing:", err)
					}
					if _, err = nncp.CopyProgressed(hsh, tarR, "check", les, ctx.ShowPrgrs); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if nncp.Base32Codec.EncodeToString(hsh.Sum(nil)) != pktName {
						ctx.LogE("bundle-rx", les, errors.New("bad checksum"), logMsg)
						continue
					}
				} else {
					tmp, err := ctx.NewTmpFileWHash()
					if err != nil {
						log.Fatalln("Error during temporary file creation:", err)
					}
					if _, err = tmp.W.Write(pktEncBuf); err != nil {
						log.Fatalln("Error during writing:", err)
					}
					if _, err = nncp.CopyProgressed(tmp.W, tarR, "check", les, ctx.ShowPrgrs); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if err = tmp.W.Flush(); err != nil {
						log.Fatalln("Error during flusing:", err)
					}
					if nncp.Base32Codec.EncodeToString(tmp.Hsh.Sum(nil)) == pktName {
						if err = tmp.Commit(dstDirPath); err != nil {
							log.Fatalln("Error during commiting:", err)
						}
					} else {
						ctx.LogE("bundle-rx", les, errors.New("bad checksum"), logMsg)
						tmp.Cancel()
						continue
					}
				}
			} else {
				if *dryRun {
					if _, err = nncp.CopyProgressed(ioutil.Discard, tarR, "Rx", les, ctx.ShowPrgrs); err != nil {
						log.Fatalln("Error during copying:", err)
					}
				} else {
					tmp, err := ctx.NewTmpFile()
					if err != nil {
						log.Fatalln("Error during temporary file creation:", err)
					}
					bufTmp := bufio.NewWriterSize(tmp, nncp.MTHBlockSize)
					if _, err = bufTmp.Write(pktEncBuf); err != nil {
						log.Fatalln("Error during writing:", err)
					}
					if _, err = nncp.CopyProgressed(bufTmp, tarR, "Rx", les, ctx.ShowPrgrs); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if err = bufTmp.Flush(); err != nil {
						log.Fatalln("Error during flushing:", err)
					}
					if !nncp.NoSync {
						if err = tmp.Sync(); err != nil {
							log.Fatalln("Error during syncing:", err)
						}
					}
					if err = tmp.Close(); err != nil {
						log.Fatalln("Error during closing:", err)
					}
					if err = os.MkdirAll(dstDirPath, os.FileMode(0777)); err != nil {
						log.Fatalln("Error during mkdir:", err)
					}
					if err = os.Rename(tmp.Name(), dstPath); err != nil {
						log.Fatalln("Error during renaming:", err)
					}
					if err = nncp.DirSync(dstDirPath); err != nil {
						log.Fatalln("Error during syncing:", err)
					}
					if ctx.HdrUsage {
						ctx.HdrWrite(pktEncBuf, dstPath)
					}
				}
			}
			for _, le := range les {
				if le.K == "FullSize" {
					les = append(les, nncp.LE{K: "Size", V: le.V})
					break
				}
			}
			ctx.LogI("bundle-rx", les, func(les nncp.LEs) string {
				return fmt.Sprintf(
					"Bundle transfer, received from %s %s (%s)",
					sender, pktName, humanize.IBytes(uint64(entry.Size)),
				)
			})
		}
	}
}
