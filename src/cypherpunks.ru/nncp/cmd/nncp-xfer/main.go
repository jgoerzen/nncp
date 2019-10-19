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

// Exchange NNCP inbound and outbounds packets with external directory.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"cypherpunks.ru/nncp"
	"github.com/davecgh/go-xdr/xdr2"
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, *logPath, *quiet, *debug)
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

	selfPath := filepath.Join(flag.Arg(0), ctx.SelfId.String())
	isBad := false
	var dir *os.File
	var fis []os.FileInfo
	sds := nncp.SDS{}
	if *txOnly {
		goto Tx
	}
	sds["xx"] = string(nncp.TRx)
	sds["dir"] = selfPath
	ctx.LogD("nncp-xfer", sds, "self")
	if _, err = os.Stat(selfPath); err != nil {
		if os.IsNotExist(err) {
			ctx.LogD("nncp-xfer", sds, "no dir")
			goto Tx
		}
		ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "stat")
		isBad = true
		goto Tx
	}
	dir, err = os.Open(selfPath)
	if err != nil {
		ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "open")
		isBad = true
		goto Tx
	}
	fis, err = dir.Readdir(0)
	dir.Close()
	if err != nil {
		ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "read")
		isBad = true
		goto Tx
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		nodeId, err := nncp.NodeIdFromString(fi.Name())
		sds["node"] = fi.Name()
		if err != nil {
			ctx.LogD("nncp-xfer", sds, "is not NodeId")
			continue
		}
		if nodeOnly != nil && *nodeId != *nodeOnly.Id {
			ctx.LogD("nncp-xfer", sds, "skip")
			continue
		}
		if _, known := ctx.Neigh[*nodeId]; !known {
			ctx.LogD("nncp-xfer", sds, "unknown")
			continue
		}
		dir, err = os.Open(filepath.Join(selfPath, fi.Name()))
		if err != nil {
			ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "open")
			isBad = true
			continue
		}
		fisInt, err := dir.Readdir(0)
		dir.Close()
		if err != nil {
			ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "read")
			isBad = true
			continue
		}
		for _, fiInt := range fisInt {
			if !fi.IsDir() {
				continue
			}
			filename := filepath.Join(dir.Name(), fiInt.Name())
			sds["file"] = filename
			delete(sds, "size")
			fd, err := os.Open(filename)
			if err != nil {
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "open")
				isBad = true
				continue
			}
			var pktEnc nncp.PktEnc
			_, err = xdr.Unmarshal(fd, &pktEnc)
			if err != nil || pktEnc.Magic != nncp.MagicNNCPEv4 {
				ctx.LogD("nncp-xfer", sds, "is not a packet")
				fd.Close()
				continue
			}
			if pktEnc.Nice > nice {
				ctx.LogD("nncp-xfer", sds, "too nice")
				fd.Close()
				continue
			}
			sds["size"] = strconv.FormatInt(fiInt.Size(), 10)
			if !ctx.IsEnoughSpace(fiInt.Size()) {
				ctx.LogE("nncp-xfer", sds, "is not enough space")
				fd.Close()
				continue
			}
			fd.Seek(0, 0)
			tmp, err := ctx.NewTmpFileWHash()
			if err != nil {
				log.Fatalln(err)
			}
			if _, err = io.CopyN(tmp.W, bufio.NewReader(fd), fiInt.Size()); err != nil {
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "copy")
				isBad = true
				fd.Close()
				tmp.Cancel()
				continue
			}
			fd.Close()
			if err = tmp.Commit(filepath.Join(
				ctx.Spool,
				nodeId.String(),
				string(nncp.TRx),
			)); err != nil {
				log.Fatalln(err)
			}
			ctx.LogI("nncp-xfer", sds, "")
			if !*keep {
				if err = os.Remove(filename); err != nil {
					ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "remove")
					isBad = true
				}
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
	sds["xx"] = string(nncp.TTx)
	for nodeId, _ := range ctx.Neigh {
		sds["node"] = nodeId
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			ctx.LogD("nncp-xfer", sds, "skip")
			continue
		}
		dirLock, err := ctx.LockDir(&nodeId, nncp.TTx)
		if err != nil {
			continue
		}
		nodePath := filepath.Join(flag.Arg(0), nodeId.String())
		sds["dir"] = nodePath
		_, err = os.Stat(nodePath)
		if err != nil {
			if os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", sds, "does not exist")
				if !*mkdir {
					ctx.UnlockDir(dirLock)
					continue
				}
				if err = os.Mkdir(nodePath, os.FileMode(0700)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "mkdir")
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "stat")
				isBad = true
				continue
			}
		}
		dstPath := filepath.Join(nodePath, ctx.SelfId.String())
		sds["dir"] = dstPath
		_, err = os.Stat(dstPath)
		if err != nil {
			if os.IsNotExist(err) {
				if err = os.Mkdir(dstPath, os.FileMode(0700)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "mkdir")
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "stat")
				isBad = true
				continue
			}
		}
		delete(sds, "dir")
		for job := range ctx.Jobs(&nodeId, nncp.TTx) {
			pktName := filepath.Base(job.Fd.Name())
			sds["pkt"] = pktName
			if job.PktEnc.Nice > nice {
				ctx.LogD("nncp-xfer", sds, "too nice")
				job.Fd.Close()
				continue
			}
			if _, err = os.Stat(filepath.Join(dstPath, pktName)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", sds, "already exists")
				job.Fd.Close()
				continue
			}
			if _, err = os.Stat(filepath.Join(dstPath, pktName+nncp.SeenSuffix)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", sds, "already exists")
				job.Fd.Close()
				continue
			}
			tmp, err := ioutil.TempFile(dstPath, "nncp-xfer")
			if err != nil {
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "mktemp")
				job.Fd.Close()
				isBad = true
				break
			}
			sds["tmp"] = tmp.Name()
			ctx.LogD("nncp-xfer", sds, "created")
			bufW := bufio.NewWriter(tmp)
			copied, err := io.Copy(bufW, bufio.NewReader(job.Fd))
			job.Fd.Close()
			if err != nil {
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "copy")
				tmp.Close()
				isBad = true
				continue
			}
			if err = bufW.Flush(); err != nil {
				tmp.Close()
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "flush")
				isBad = true
				continue
			}
			if err = tmp.Sync(); err != nil {
				tmp.Close()
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "sync")
				isBad = true
				continue
			}
			tmp.Close()
			if err = os.Rename(tmp.Name(), filepath.Join(dstPath, pktName)); err != nil {
				ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "rename")
				isBad = true
				continue
			}
			os.Remove(filepath.Join(dstPath, pktName+".part"))
			delete(sds, "tmp")
			ctx.LogI("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{
				"size": strconv.FormatInt(copied, 10),
			}), "")
			if !*keep {
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("nncp-xfer", nncp.SdsAdd(sds, nncp.SDS{"err": err}), "remove")
					isBad = true
				}
			}
		}
		ctx.UnlockDir(dirLock)
	}
	if isBad {
		os.Exit(1)
	}
}
