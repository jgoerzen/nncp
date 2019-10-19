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

// Create/digest stream of NNCP encrypted packets.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cypherpunks.ru/nncp"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
)

const (
	CopyBufSize = 1 << 17
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, *logPath, *quiet, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}

	nodeIds := make(map[nncp.NodeId]struct{}, flag.NArg())
	for i := 0; i < flag.NArg(); i++ {
		node, err := ctx.FindNode(flag.Arg(i))
		if err != nil {
			log.Fatalln("Invalid specified:", err)
		}
		nodeIds[*node.Id] = struct{}{}
	}

	sds := nncp.SDS{}
	if *doTx {
		sds["xx"] = string(nncp.TTx)
		var pktName string
		bufStdout := bufio.NewWriter(os.Stdout)
		tarWr := tar.NewWriter(bufStdout)
		for nodeId, _ := range nodeIds {
			sds["node"] = nodeId.String()
			for job := range ctx.Jobs(&nodeId, nncp.TTx) {
				pktName = filepath.Base(job.Fd.Name())
				sds["pkt"] = pktName
				if job.PktEnc.Nice > nice {
					ctx.LogD("nncp-bundle", sds, "too nice")
					job.Fd.Close()
					continue
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
				if _, err = io.Copy(tarWr, job.Fd); err != nil {
					log.Fatalln("Error during copying to tar:", err)
				}
				job.Fd.Close()
				if err = tarWr.Flush(); err != nil {
					log.Fatalln("Error during tar flushing:", err)
				}
				if err = bufStdout.Flush(); err != nil {
					log.Fatalln("Error during stdout flushing:", err)
				}
				if *doDelete {
					if err = os.Remove(job.Fd.Name()); err != nil {
						log.Fatalln("Error during deletion:", err)
					}
				}
				ctx.LogI("nncp-bundle", nncp.SdsAdd(sds, nncp.SDS{
					"size": strconv.FormatInt(job.Size, 10),
				}), "")
			}
		}
		if err = tarWr.Close(); err != nil {
			log.Fatalln("Error during tar closing:", err)
		}
	} else {
		bufStdin := bufio.NewReaderSize(os.Stdin, CopyBufSize*2)
		var peeked []byte
		var prefixIdx int
		var tarR *tar.Reader
		var entry *tar.Header
		var exists bool
		pktEncBuf := make([]byte, nncp.PktEncOverhead)
		var pktEnc *nncp.PktEnc
		var pktName string
		var selfPath string
		var dstPath string
		for {
			peeked, err = bufStdin.Peek(CopyBufSize)
			if err != nil && err != io.EOF {
				log.Fatalln("Error during reading:", err)
			}
			prefixIdx = bytes.Index(peeked, []byte(nncp.NNCPBundlePrefix))
			if prefixIdx == -1 {
				if err == io.EOF {
					break
				}
				bufStdin.Discard(bufStdin.Buffered() - (len(nncp.NNCPBundlePrefix) - 1))
				continue
			}
			bufStdin.Discard(prefixIdx)
			tarR = tar.NewReader(bufStdin)
			sds["xx"] = string(nncp.TRx)
			entry, err = tarR.Next()
			if err != nil {
				if err != io.EOF {
					ctx.LogD(
						"nncp-bundle",
						nncp.SdsAdd(sds, nncp.SDS{"err": err}),
						"error reading tar",
					)
				}
				continue
			}
			if entry.Typeflag != tar.TypeDir {
				ctx.LogD("nncp-bundle", sds, "Expected NNCP/")
				continue
			}
			entry, err = tarR.Next()
			if err != nil {
				if err != io.EOF {
					ctx.LogD(
						"nncp-bundle",
						nncp.SdsAdd(sds, nncp.SDS{"err": err}),
						"error reading tar",
					)
				}
				continue
			}
			sds["pkt"] = entry.Name
			if entry.Size < nncp.PktEncOverhead {
				ctx.LogD("nncp-bundle", sds, "Too small packet")
				continue
			}
			pktName = filepath.Base(entry.Name)
			if _, err = nncp.FromBase32(pktName); err != nil {
				ctx.LogD("nncp-bundle", sds, "Bad packet name")
				continue
			}
			if _, err = io.ReadFull(tarR, pktEncBuf); err != nil {
				ctx.LogD("nncp-bundle", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "read")
				continue
			}
			if _, err = xdr.Unmarshal(bytes.NewReader(pktEncBuf), &pktEnc); err != nil {
				ctx.LogD("nncp-bundle", sds, "Bad packet structure")
				continue
			}
			if pktEnc.Magic != nncp.MagicNNCPEv4 {
				ctx.LogD("nncp-bundle", sds, "Bad packet magic number")
				continue
			}
			if pktEnc.Nice > nice {
				ctx.LogD("nncp-bundle", sds, "too nice")
				continue
			}
			if *pktEnc.Sender == *ctx.SelfId && *doDelete {
				if len(nodeIds) > 0 {
					if _, exists = nodeIds[*pktEnc.Recipient]; !exists {
						ctx.LogD("nncp-bundle", sds, "Recipient is not requested")
						continue
					}
				}
				nodeId32 := nncp.ToBase32(pktEnc.Recipient[:])
				sds["xx"] = string(nncp.TTx)
				sds["node"] = nodeId32
				sds["pkt"] = pktName
				dstPath = filepath.Join(
					ctx.Spool,
					nodeId32,
					string(nncp.TTx),
					pktName,
				)
				if _, err = os.Stat(dstPath); err != nil {
					ctx.LogD("nncp-bundle", sds, "Packet is already missing")
					continue
				}
				hsh, err := blake2b.New256(nil)
				if err != nil {
					log.Fatalln("Error during hasher creation:", err)
				}
				if _, err = hsh.Write(pktEncBuf); err != nil {
					log.Fatalln("Error during writing:", err)
				}
				if _, err = io.Copy(hsh, tarR); err != nil {
					log.Fatalln("Error during copying:", err)
				}
				if nncp.ToBase32(hsh.Sum(nil)) == pktName {
					ctx.LogI("nncp-bundle", sds, "removed")
					if !*dryRun {
						os.Remove(dstPath)
					}
				} else {
					ctx.LogE("nncp-bundle", sds, "bad checksum")
				}
				continue
			}
			if *pktEnc.Recipient != *ctx.SelfId {
				ctx.LogD("nncp-bundle", sds, "Unknown recipient")
				continue
			}
			if len(nodeIds) > 0 {
				if _, exists = nodeIds[*pktEnc.Sender]; !exists {
					ctx.LogD("nncp-bundle", sds, "Sender is not requested")
					continue
				}
			}
			sds["node"] = nncp.ToBase32(pktEnc.Recipient[:])
			sds["pkt"] = pktName
			selfPath = filepath.Join(ctx.Spool, ctx.SelfId.String(), string(nncp.TRx))
			dstPath = filepath.Join(selfPath, pktName)
			if _, err = os.Stat(dstPath); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-bundle", sds, "Packet already exists")
				continue
			}
			if _, err = os.Stat(dstPath + nncp.SeenSuffix); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-bundle", sds, "Packet already exists")
				continue
			}
			if *doCheck {
				if *dryRun {
					hsh, err := blake2b.New256(nil)
					if err != nil {
						log.Fatalln("Error during hasher creation:", err)
					}
					if _, err = hsh.Write(pktEncBuf); err != nil {
						log.Fatalln("Error during writing:", err)
					}
					if _, err = io.Copy(hsh, tarR); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if nncp.ToBase32(hsh.Sum(nil)) != pktName {
						ctx.LogE("nncp-bundle", sds, "bad checksum")
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
					if _, err = io.Copy(tmp.W, tarR); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if err = tmp.W.Flush(); err != nil {
						log.Fatalln("Error during flusing:", err)
					}
					if nncp.ToBase32(tmp.Hsh.Sum(nil)) == pktName {
						if err = tmp.Commit(selfPath); err != nil {
							log.Fatalln("Error during commiting:", err)
						}
					} else {
						ctx.LogE("nncp-bundle", sds, "bad checksum")
						tmp.Cancel()
						continue
					}
				}
			} else {
				if *dryRun {
					if _, err = io.Copy(ioutil.Discard, tarR); err != nil {
						log.Fatalln("Error during copying:", err)
					}
				} else {
					tmp, err := ctx.NewTmpFile()
					if err != nil {
						log.Fatalln("Error during temporary file creation:", err)
					}
					bufTmp := bufio.NewWriterSize(tmp, CopyBufSize)
					if _, err = bufTmp.Write(pktEncBuf); err != nil {
						log.Fatalln("Error during writing:", err)
					}
					if _, err = io.Copy(bufTmp, tarR); err != nil {
						log.Fatalln("Error during copying:", err)
					}
					if err = bufTmp.Flush(); err != nil {
						log.Fatalln("Error during flushing:", err)
					}
					if err = tmp.Sync(); err != nil {
						log.Fatalln("Error during syncing:", err)
					}
					tmp.Close()
					if err = os.MkdirAll(selfPath, os.FileMode(0700)); err != nil {
						log.Fatalln("Error during mkdir:", err)
					}
					if err = os.Rename(tmp.Name(), dstPath); err != nil {
						log.Fatalln("Error during renaming:", err)
					}
				}
			}
			ctx.LogI("nncp-bundle", nncp.SdsAdd(sds, nncp.SDS{
				"size": strconv.FormatInt(entry.Size, 10),
			}), "")
		}
	}
}
