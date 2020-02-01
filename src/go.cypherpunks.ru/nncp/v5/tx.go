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

package nncp

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxFileSize = 1 << 62

	TarBlockSize = 512
	TarExt       = ".tar"
)

func (ctx *Ctx) Tx(
	node *Node,
	pkt *Pkt,
	nice uint8,
	size, minSize int64,
	src io.Reader,
	pktName string,
) (*Node, error) {
	hops := make([]*Node, 0, 1+len(node.Via))
	hops = append(hops, node)
	lastNode := node
	for i := len(node.Via); i > 0; i-- {
		lastNode = ctx.Neigh[*node.Via[i-1]]
		hops = append(hops, lastNode)
	}
	expectedSize := size
	for i := 0; i < len(hops); i++ {
		expectedSize = PktEncOverhead + PktSizeOverhead + sizeWithTags(PktOverhead+expectedSize)
	}
	padSize := minSize - expectedSize
	if padSize < 0 {
		padSize = 0
	}
	if !ctx.IsEnoughSpace(size + padSize) {
		return nil, errors.New("is not enough space")
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return nil, err
	}

	errs := make(chan error)
	curSize := size
	pipeR, pipeW := io.Pipe()
	go func(size int64, src io.Reader, dst io.WriteCloser) {
		ctx.LogD("tx", SDS{
			"node": hops[0].Id,
			"nice": int(nice),
			"size": size,
		}, "wrote")
		errs <- PktEncWrite(ctx.Self, hops[0], pkt, nice, size, padSize, src, dst)
		dst.Close() // #nosec G104
	}(curSize, src, pipeW)
	curSize = PktEncOverhead + PktSizeOverhead + sizeWithTags(PktOverhead+curSize) + padSize

	var pipeRPrev io.Reader
	for i := 1; i < len(hops); i++ {
		pktTrns, _ := NewPkt(PktTypeTrns, 0, hops[i-1].Id[:])
		pipeRPrev = pipeR
		pipeR, pipeW = io.Pipe()
		go func(node *Node, pkt *Pkt, size int64, src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", SDS{
				"node": node.Id,
				"nice": int(nice),
				"size": size,
			}, "trns wrote")
			errs <- PktEncWrite(ctx.Self, node, pkt, nice, size, 0, src, dst)
			dst.Close() // #nosec G104
		}(hops[i], pktTrns, curSize, pipeRPrev, pipeW)
		curSize = PktEncOverhead + PktSizeOverhead + sizeWithTags(PktOverhead+curSize)
	}
	go func() {
		_, err := CopyProgressed(
			tmp.W, pipeR, "Tx",
			SDS{"pkt": pktName, "fullsize": curSize},
			ctx.ShowPrgrs,
		)
		errs <- err
	}()
	for i := 0; i <= len(hops); i++ {
		err = <-errs
		if err != nil {
			tmp.Fd.Close() // #nosec G104
			return nil, err
		}
	}
	nodePath := filepath.Join(ctx.Spool, lastNode.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	os.Symlink(nodePath, filepath.Join(ctx.Spool, lastNode.Name)) // #nosec G104
	return lastNode, err
}

type DummyCloser struct{}

func (dc DummyCloser) Close() error { return nil }

func prepareTxFile(srcPath string) (reader io.Reader, closer io.Closer, fileSize int64, archived bool, rerr error) {
	if srcPath == "-" {
		// Read content from stdin, saving to temporary file, encrypting
		// on the fly
		src, err := ioutil.TempFile("", "nncp-file")
		if err != nil {
			rerr = err
			return
		}
		os.Remove(src.Name()) // #nosec G104
		tmpW := bufio.NewWriter(src)
		tmpKey := make([]byte, chacha20poly1305.KeySize)
		if _, rerr = rand.Read(tmpKey[:]); rerr != nil {
			return
		}
		aead, err := chacha20poly1305.New(tmpKey)
		if err != nil {
			rerr = err
			return
		}
		nonce := make([]byte, aead.NonceSize())
		written, err := aeadProcess(aead, nonce, true, bufio.NewReader(os.Stdin), tmpW)
		if err != nil {
			rerr = err
			return
		}
		fileSize = int64(written)
		if err = tmpW.Flush(); err != nil {
			rerr = err
			return
		}
		if _, err = src.Seek(0, io.SeekStart); err != nil {
			rerr = err
			return
		}
		r, w := io.Pipe()
		go func() {
			if _, err := aeadProcess(aead, nonce, false, bufio.NewReader(src), w); err != nil {
				w.CloseWithError(err) // #nosec G104
			}
		}()
		reader = r
		closer = src
		return
	}

	srcStat, err := os.Stat(srcPath)
	if err != nil {
		rerr = err
		return
	}
	mode := srcStat.Mode()

	if mode.IsRegular() {
		// It is regular file, just send it
		src, err := os.Open(srcPath)
		if err != nil {
			rerr = err
			return
		}
		fileSize = srcStat.Size()
		reader = bufio.NewReader(src)
		closer = src
		return
	}

	if !mode.IsDir() {
		rerr = errors.New("unsupported file type")
		return
	}

	// It is directory, create PAX archive with its contents
	archived = true
	basePath := filepath.Base(srcPath)
	rootPath, err := filepath.Abs(srcPath)
	if err != nil {
		rerr = err
		return
	}
	type einfo struct {
		path    string
		modTime time.Time
		size    int64
	}
	dirs := make([]einfo, 0, 1<<10)
	files := make([]einfo, 0, 1<<10)
	rerr = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// directory header, PAX record header+contents
			fileSize += TarBlockSize + 2*TarBlockSize
			dirs = append(dirs, einfo{path: path, modTime: info.ModTime()})
		} else {
			// file header, PAX record header+contents, file content
			fileSize += TarBlockSize + 2*TarBlockSize + info.Size()
			if n := info.Size() % TarBlockSize; n != 0 {
				fileSize += TarBlockSize - n // padding
			}
			files = append(files, einfo{
				path:    path,
				modTime: info.ModTime(),
				size:    info.Size(),
			})
		}
		return nil
	})
	if rerr != nil {
		return
	}

	r, w := io.Pipe()
	reader = r
	closer = DummyCloser{}
	fileSize += 2 * TarBlockSize // termination block

	go func() error {
		tarWr := tar.NewWriter(w)
		hdr := tar.Header{
			Typeflag: tar.TypeDir,
			Mode:     0777,
			PAXRecords: map[string]string{
				"comment": "Autogenerated by " + VersionGet(),
			},
			Format: tar.FormatPAX,
		}
		for _, e := range dirs {
			hdr.Name = basePath + e.path[len(rootPath):]
			hdr.ModTime = e.modTime
			if err = tarWr.WriteHeader(&hdr); err != nil {
				return w.CloseWithError(err)
			}
		}
		hdr.Typeflag = tar.TypeReg
		hdr.Mode = 0666
		for _, e := range files {
			hdr.Name = basePath + e.path[len(rootPath):]
			hdr.ModTime = e.modTime
			hdr.Size = e.size
			if err = tarWr.WriteHeader(&hdr); err != nil {
				return w.CloseWithError(err)
			}
			fd, err := os.Open(e.path)
			if err != nil {
				fd.Close() // #nosec G104
				return w.CloseWithError(err)
			}
			if _, err = io.Copy(tarWr, bufio.NewReader(fd)); err != nil {
				fd.Close() // #nosec G104
				return w.CloseWithError(err)
			}
			fd.Close() // #nosec G104
		}
		if err = tarWr.Close(); err != nil {
			return w.CloseWithError(err)
		}
		return w.Close()
	}()
	return
}

func (ctx *Ctx) TxFile(
	node *Node,
	nice uint8,
	srcPath, dstPath string,
	chunkSize int64,
	minSize, maxSize int64,
) error {
	dstPathSpecified := false
	if dstPath == "" {
		if srcPath == "-" {
			return errors.New("Must provide destination filename")
		}
		dstPath = filepath.Base(srcPath)
	} else {
		dstPathSpecified = true
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	reader, closer, fileSize, archived, err := prepareTxFile(srcPath)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		return err
	}
	if fileSize > maxSize {
		return errors.New("Too big than allowed")
	}
	if archived && !dstPathSpecified {
		dstPath += TarExt
	}

	if fileSize <= chunkSize {
		pkt, err := NewPkt(PktTypeFile, nice, []byte(dstPath))
		if err != nil {
			return err
		}
		_, err = ctx.Tx(node, pkt, nice, fileSize, minSize, reader, dstPath)
		sds := SDS{
			"type": "file",
			"node": node.Id,
			"nice": int(nice),
			"src":  srcPath,
			"dst":  dstPath,
			"size": fileSize,
		}
		if err == nil {
			ctx.LogI("tx", sds, "sent")
		} else {
			ctx.LogE("tx", sds, err, "sent")
		}
		return err
	}

	leftSize := fileSize
	metaPkt := ChunkedMeta{
		Magic:     MagicNNCPMv1,
		FileSize:  uint64(fileSize),
		ChunkSize: uint64(chunkSize),
		Checksums: make([][32]byte, 0, (fileSize/chunkSize)+1),
	}
	for i := int64(0); i < (fileSize/chunkSize)+1; i++ {
		hsh := new([32]byte)
		metaPkt.Checksums = append(metaPkt.Checksums, *hsh)
	}
	var sizeToSend int64
	var hsh hash.Hash
	var pkt *Pkt
	var chunkNum int
	var path string
	for {
		if leftSize <= chunkSize {
			sizeToSend = leftSize
		} else {
			sizeToSend = chunkSize
		}
		path = dstPath + ChunkedSuffixPart + strconv.Itoa(chunkNum)
		pkt, err = NewPkt(PktTypeFile, nice, []byte(path))
		if err != nil {
			return err
		}
		hsh, err = blake2b.New256(nil)
		if err != nil {
			return err
		}
		_, err = ctx.Tx(
			node,
			pkt,
			nice,
			sizeToSend,
			minSize,
			io.TeeReader(reader, hsh),
			path,
		)
		sds := SDS{
			"type": "file",
			"node": node.Id,
			"nice": int(nice),
			"src":  srcPath,
			"dst":  path,
			"size": sizeToSend,
		}
		if err == nil {
			ctx.LogI("tx", sds, "sent")
		} else {
			ctx.LogE("tx", sds, err, "sent")
			return err
		}
		hsh.Sum(metaPkt.Checksums[chunkNum][:0])
		leftSize -= sizeToSend
		chunkNum++
		if leftSize == 0 {
			break
		}
	}
	var metaBuf bytes.Buffer
	_, err = xdr.Marshal(&metaBuf, metaPkt)
	if err != nil {
		return err
	}
	path = dstPath + ChunkedSuffixMeta
	pkt, err = NewPkt(PktTypeFile, nice, []byte(path))
	if err != nil {
		return err
	}
	metaPktSize := int64(metaBuf.Len())
	_, err = ctx.Tx(node, pkt, nice, metaPktSize, minSize, &metaBuf, path)
	sds := SDS{
		"type": "file",
		"node": node.Id,
		"nice": int(nice),
		"src":  srcPath,
		"dst":  path,
		"size": metaPktSize,
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		ctx.LogE("tx", sds, err, "sent")
	}
	return err
}

func (ctx *Ctx) TxFreq(
	node *Node,
	nice, replyNice uint8,
	srcPath, dstPath string,
	minSize int64) error {
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	srcPath = filepath.Clean(srcPath)
	if filepath.IsAbs(srcPath) {
		return errors.New("Relative source path required")
	}
	pkt, err := NewPkt(PktTypeFreq, replyNice, []byte(srcPath))
	if err != nil {
		return err
	}
	src := strings.NewReader(dstPath)
	size := int64(src.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, src, srcPath)
	sds := SDS{
		"type":      "freq",
		"node":      node.Id,
		"nice":      int(nice),
		"replynice": int(replyNice),
		"src":       srcPath,
		"dst":       dstPath,
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		ctx.LogE("tx", sds, err, "sent")
	}
	return err
}

func (ctx *Ctx) TxExec(
	node *Node,
	nice, replyNice uint8,
	handle string,
	args []string,
	in io.Reader,
	minSize int64,
) error {
	path := make([][]byte, 0, 1+len(args))
	path = append(path, []byte(handle))
	for _, arg := range args {
		path = append(path, []byte(arg))
	}
	pkt, err := NewPkt(PktTypeExec, replyNice, bytes.Join(path, []byte{0}))
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	compressor, err := zstd.NewWriter(
		&compressed,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
	)
	if err != nil {
		return err
	}
	if _, err = io.Copy(compressor, in); err != nil {
		compressor.Close() // #nosec G104
		return err
	}
	if err = compressor.Close(); err != nil {
		return err
	}
	size := int64(compressed.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, &compressed, handle)
	sds := SDS{
		"type":      "exec",
		"node":      node.Id,
		"nice":      int(nice),
		"replynice": int(replyNice),
		"dst":       strings.Join(append([]string{handle}, args...), " "),
		"size":      size,
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		ctx.LogE("tx", sds, err, "sent")
	}
	return err
}

func (ctx *Ctx) TxTrns(node *Node, nice uint8, size int64, src io.Reader) error {
	sds := SDS{
		"type": "trns",
		"node": node.Id,
		"nice": int(nice),
		"size": size,
	}
	ctx.LogD("tx", sds, "taken")
	if !ctx.IsEnoughSpace(size) {
		err := errors.New("is not enough space")
		ctx.LogE("tx", sds, err, err.Error())
		return err
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return err
	}
	if _, err = CopyProgressed(
		tmp.W, src, "Tx trns",
		SDS{"pkt": node.Id.String(), "fullsize": size},
		ctx.ShowPrgrs,
	); err != nil {
		return err
	}
	nodePath := filepath.Join(ctx.Spool, node.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		ctx.LogI("tx", SdsAdd(sds, SDS{"err": err}), "sent")
	}
	os.Symlink(nodePath, filepath.Join(ctx.Spool, node.Name)) // #nosec G104
	return err
}
