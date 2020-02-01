/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2020 Sergey Matveev <stargrave@stargrave.org>

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

// Reassembly chunked file.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v5"
	"golang.org/x/crypto/blake2b"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-reass -- reassemble chunked files\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [FILE.nncp.meta]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Neither FILE, nor -node nor -all can be set simultaneously,
but at least one of them must be specified.
`)
}

func process(ctx *nncp.Ctx, path string, keep, dryRun, stdout, dumpMeta bool) bool {
	fd, err := os.Open(path)
	defer fd.Close()
	if err != nil {
		log.Fatalln("Can not open file:", err)
	}
	var metaPkt nncp.ChunkedMeta
	if _, err = xdr.Unmarshal(fd, &metaPkt); err != nil {
		ctx.LogE("nncp-reass", nncp.SDS{"path": path}, err, "bad meta file")
		return false
	}
	fd.Close() // #nosec G104
	if metaPkt.Magic != nncp.MagicNNCPMv1 {
		ctx.LogE("nncp-reass", nncp.SDS{"path": path}, nncp.BadMagic, "")
		return false
	}

	metaName := filepath.Base(path)
	if !strings.HasSuffix(metaName, nncp.ChunkedSuffixMeta) {
		ctx.LogE("nncp-reass", nncp.SDS{"path": path}, errors.New("invalid filename suffix"), "")
		return false
	}
	mainName := strings.TrimSuffix(metaName, nncp.ChunkedSuffixMeta)
	if dumpMeta {
		fmt.Printf("Original filename: %s\n", mainName)
		fmt.Printf(
			"File size: %s (%d bytes)\n",
			humanize.IBytes(metaPkt.FileSize),
			metaPkt.FileSize,
		)
		fmt.Printf(
			"Chunk size: %s (%d bytes)\n",
			humanize.IBytes(metaPkt.ChunkSize),
			metaPkt.ChunkSize,
		)
		fmt.Printf("Number of chunks: %d\n", len(metaPkt.Checksums))
		fmt.Println("Checksums:")
		for chunkNum, checksum := range metaPkt.Checksums {
			fmt.Printf("\t%d: %s\n", chunkNum, hex.EncodeToString(checksum[:]))
		}
		return true
	}
	mainDir := filepath.Dir(path)

	chunksPaths := make([]string, 0, len(metaPkt.Checksums))
	for i := 0; i < len(metaPkt.Checksums); i++ {
		chunksPaths = append(
			chunksPaths,
			filepath.Join(mainDir, mainName+nncp.ChunkedSuffixPart+strconv.Itoa(i)),
		)
	}

	allChunksExist := true
	for chunkNum, chunkPath := range chunksPaths {
		fi, err := os.Stat(chunkPath)
		if err != nil && os.IsNotExist(err) {
			ctx.LogI("nncp-reass", nncp.SDS{"path": path, "chunk": chunkNum}, "missing")
			allChunksExist = false
			continue
		}
		var badSize bool
		if chunkNum+1 == len(chunksPaths) {
			badSize = uint64(fi.Size()) != metaPkt.FileSize%metaPkt.ChunkSize
		} else {
			badSize = uint64(fi.Size()) != metaPkt.ChunkSize
		}
		if badSize {
			ctx.LogE(
				"nncp-reass",
				nncp.SDS{"path": path, "chunk": chunkNum},
				errors.New("invalid size"), "",
			)
			allChunksExist = false
		}
	}
	if !allChunksExist {
		return false
	}

	var hsh hash.Hash
	allChecksumsGood := true
	for chunkNum, chunkPath := range chunksPaths {
		fd, err = os.Open(chunkPath)
		if err != nil {
			log.Fatalln("Can not open file:", err)
		}
		fi, err := fd.Stat()
		if err != nil {
			log.Fatalln("Can not stat file:", err)
		}
		hsh, err = blake2b.New256(nil)
		if err != nil {
			log.Fatalln(err)
		}
		if _, err = nncp.CopyProgressed(
			hsh, bufio.NewReader(fd), "check",
			nncp.SDS{
				"pkt":      chunkPath,
				"fullsize": fi.Size(),
			},
			ctx.ShowPrgrs,
		); err != nil {
			log.Fatalln(err)
		}
		fd.Close() // #nosec G104
		if bytes.Compare(hsh.Sum(nil), metaPkt.Checksums[chunkNum][:]) != 0 {
			ctx.LogE(
				"nncp-reass",
				nncp.SDS{"path": path, "chunk": chunkNum},
				errors.New("checksum is bad"), "",
			)
			allChecksumsGood = false
		}
	}
	if !allChecksumsGood {
		return false
	}
	if dryRun {
		ctx.LogI("nncp-reass", nncp.SDS{"path": path}, "ready")
		return true
	}

	var dst io.Writer
	var tmp *os.File
	var sds nncp.SDS
	if stdout {
		dst = os.Stdout
		sds = nncp.SDS{"path": path}
	} else {
		tmp, err = nncp.TempFile(mainDir, "reass")
		if err != nil {
			log.Fatalln(err)
		}
		sds = nncp.SDS{"path": path, "tmp": tmp.Name()}
		ctx.LogD("nncp-reass", sds, "created")
		dst = tmp
	}
	dstW := bufio.NewWriter(dst)

	hasErrors := false
	for chunkNum, chunkPath := range chunksPaths {
		fd, err = os.Open(chunkPath)
		if err != nil {
			log.Fatalln("Can not open file:", err)
		}
		fi, err := fd.Stat()
		if err != nil {
			log.Fatalln("Can not stat file:", err)
		}
		if _, err = nncp.CopyProgressed(
			dstW, bufio.NewReader(fd), "reass",
			nncp.SDS{
				"pkt":      chunkPath,
				"fullsize": fi.Size(),
			},
			ctx.ShowPrgrs,
		); err != nil {
			log.Fatalln(err)
		}
		fd.Close() // #nosec G104
		if !keep {
			if err = os.Remove(chunkPath); err != nil {
				ctx.LogE("nncp-reass", nncp.SdsAdd(sds, nncp.SDS{"chunk": chunkNum}), err, "")
				hasErrors = true
			}
		}
	}
	if err = dstW.Flush(); err != nil {
		log.Fatalln("Can not flush:", err)
	}
	if tmp != nil {
		if err = tmp.Sync(); err != nil {
			log.Fatalln("Can not sync:", err)
		}
		if err = tmp.Close(); err != nil {
			log.Fatalln("Can not close:", err)
		}
	}
	ctx.LogD("nncp-reass", sds, "written")
	if !keep {
		if err = os.Remove(path); err != nil {
			ctx.LogE("nncp-reass", sds, err, "")
			hasErrors = true
		}
	}
	if stdout {
		ctx.LogI("nncp-reass", nncp.SDS{"path": path}, "done")
		return !hasErrors
	}

	dstPathOrig := filepath.Join(mainDir, mainName)
	dstPath := dstPathOrig
	dstPathCtr := 0
	for {
		if _, err = os.Stat(dstPath); err != nil {
			if os.IsNotExist(err) {
				break
			}
			log.Fatalln(err)
		}
		dstPath = dstPathOrig + "." + strconv.Itoa(dstPathCtr)
		dstPathCtr++
	}
	if err = os.Rename(tmp.Name(), dstPath); err != nil {
		log.Fatalln(err)
	}
	if err = nncp.DirSync(mainDir); err != nil {
		log.Fatalln(err)
	}
	ctx.LogI("nncp-reass", nncp.SDS{"path": path}, "done")
	return !hasErrors
}

func findMetas(ctx *nncp.Ctx, dirPath string) []string {
	dir, err := os.Open(dirPath)
	defer dir.Close()
	if err != nil {
		ctx.LogE("nncp-reass", nncp.SDS{"path": dirPath}, err, "")
		return nil
	}
	fis, err := dir.Readdir(0)
	dir.Close() // #nosec G104
	if err != nil {
		ctx.LogE("nncp-reass", nncp.SDS{"path": dirPath}, err, "")
		return nil
	}
	metaPaths := make([]string, 0)
	for _, fi := range fis {
		if strings.HasSuffix(fi.Name(), nncp.ChunkedSuffixMeta) {
			metaPaths = append(metaPaths, filepath.Join(dirPath, fi.Name()))
		}
	}
	return metaPaths
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		allNodes  = flag.Bool("all", false, "Process all found chunked files for all nodes")
		nodeRaw   = flag.String("node", "", "Process all found chunked files for that node")
		keep      = flag.Bool("keep", false, "Do not remove chunks while assembling")
		dryRun    = flag.Bool("dryrun", false, "Do not assemble whole file")
		dumpMeta  = flag.Bool("dump", false, "Print decoded human-readable FILE.nncp.meta")
		stdout    = flag.Bool("stdout", false, "Output reassembled FILE to stdout")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
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

	if !(*allNodes || nodeOnly != nil || flag.NArg() > 0) {
		usage()
		os.Exit(1)
	}
	if flag.NArg() > 0 && (*allNodes || nodeOnly != nil) {
		usage()
		os.Exit(1)
	}
	if *allNodes && nodeOnly != nil {
		usage()
		os.Exit(1)
	}

	ctx.Umask()

	if flag.NArg() > 0 {
		if process(ctx, flag.Arg(0), *keep, *dryRun, *stdout, *dumpMeta) {
			return
		}
		os.Exit(1)
	}

	hasErrors := false
	if nodeOnly == nil {
		seenMetaPaths := make(map[string]struct{})
		for _, node := range ctx.Neigh {
			if node.Incoming == nil {
				continue
			}
			for _, metaPath := range findMetas(ctx, *node.Incoming) {
				if _, seen := seenMetaPaths[metaPath]; seen {
					continue
				}
				if !process(ctx, metaPath, *keep, *dryRun, false, false) {
					hasErrors = true
				}
				seenMetaPaths[metaPath] = struct{}{}
			}
		}
	} else {
		if nodeOnly.Incoming == nil {
			log.Fatalln("Specified -node does not allow incoming")
		}
		for _, metaPath := range findMetas(ctx, *nodeOnly.Incoming) {
			if !process(ctx, metaPath, *keep, *dryRun, false, false) {
				hasErrors = true
			}
		}
	}
	if hasErrors {
		os.Exit(1)
	}
}
