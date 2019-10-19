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

package nncp

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

func (ctx *Ctx) Tx(
	node *Node,
	pkt *Pkt,
	nice uint8,
	size, minSize int64,
	src io.Reader,
) (*Node, error) {
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return nil, err
	}
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
	errs := make(chan error)
	curSize := size
	pipeR, pipeW := io.Pipe()
	go func(size int64, src io.Reader, dst io.WriteCloser) {
		ctx.LogD("tx", SDS{
			"node": hops[0].Id,
			"nice": strconv.Itoa(int(nice)),
			"size": strconv.FormatInt(size, 10),
		}, "wrote")
		errs <- PktEncWrite(ctx.Self, hops[0], pkt, nice, size, padSize, src, dst)
		dst.Close()
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
				"nice": strconv.Itoa(int(nice)),
				"size": strconv.FormatInt(size, 10),
			}, "trns wrote")
			errs <- PktEncWrite(ctx.Self, node, pkt, nice, size, 0, src, dst)
			dst.Close()
		}(hops[i], pktTrns, curSize, pipeRPrev, pipeW)
		curSize = PktEncOverhead + PktSizeOverhead + sizeWithTags(PktOverhead+curSize)
	}
	go func() {
		_, err := io.Copy(tmp.W, pipeR)
		errs <- err
	}()
	for i := 0; i <= len(hops); i++ {
		err = <-errs
		if err != nil {
			tmp.Fd.Close()
			return nil, err
		}
	}
	nodePath := filepath.Join(ctx.Spool, lastNode.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	os.Symlink(nodePath, filepath.Join(ctx.Spool, lastNode.Name))
	return lastNode, err
}

func prepareTxFile(srcPath string) (io.Reader, *os.File, int64, error) {
	var reader io.Reader
	var src *os.File
	var fileSize int64
	var err error
	if srcPath == "-" {
		src, err = ioutil.TempFile("", "nncp-file")
		if err != nil {
			return nil, nil, 0, err
		}
		os.Remove(src.Name())
		tmpW := bufio.NewWriter(src)
		tmpKey := make([]byte, chacha20poly1305.KeySize)
		if _, err = rand.Read(tmpKey[:]); err != nil {
			return nil, nil, 0, err
		}
		aead, err := chacha20poly1305.New(tmpKey)
		if err != nil {
			return nil, nil, 0, err
		}
		nonce := make([]byte, aead.NonceSize())
		written, err := aeadProcess(aead, nonce, true, bufio.NewReader(os.Stdin), tmpW)
		if err != nil {
			return nil, nil, 0, err
		}
		fileSize = int64(written)
		if err = tmpW.Flush(); err != nil {
			return nil, nil, 0, err
		}
		src.Seek(0, io.SeekStart)
		r, w := io.Pipe()
		go func() {
			if _, err := aeadProcess(aead, nonce, false, bufio.NewReader(src), w); err != nil {
				panic(err)
			}
		}()
		reader = r
	} else {
		src, err = os.Open(srcPath)
		if err != nil {
			return nil, nil, 0, err
		}
		srcStat, err := src.Stat()
		if err != nil {
			return nil, nil, 0, err
		}
		fileSize = srcStat.Size()
		reader = bufio.NewReader(src)
	}
	return reader, src, fileSize, nil
}

func (ctx *Ctx) TxFile(node *Node, nice uint8, srcPath, dstPath string, minSize int64) error {
	if dstPath == "" {
		if srcPath == "-" {
			return errors.New("Must provide destination filename")
		}
		dstPath = filepath.Base(srcPath)
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	pkt, err := NewPkt(PktTypeFile, nice, []byte(dstPath))
	if err != nil {
		return err
	}
	reader, src, fileSize, err := prepareTxFile(srcPath)
	if src != nil {
		defer src.Close()
	}
	if err != nil {
		return err
	}
	_, err = ctx.Tx(node, pkt, nice, fileSize, minSize, reader)
	sds := SDS{
		"type": "file",
		"node": node.Id,
		"nice": strconv.Itoa(int(nice)),
		"src":  srcPath,
		"dst":  dstPath,
		"size": strconv.FormatInt(fileSize, 10),
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		sds["err"] = err
		ctx.LogE("tx", sds, "sent")
	}
	return err
}

func (ctx *Ctx) TxFileChunked(
	node *Node,
	nice uint8,
	srcPath, dstPath string,
	minSize int64,
	chunkSize int64,
) error {
	if dstPath == "" {
		if srcPath == "-" {
			return errors.New("Must provide destination filename")
		}
		dstPath = filepath.Base(srcPath)
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	reader, src, fileSize, err := prepareTxFile(srcPath)
	if src != nil {
		defer src.Close()
	}
	if err != nil {
		return err
	}

	if fileSize <= chunkSize {
		pkt, err := NewPkt(PktTypeFile, nice, []byte(dstPath))
		if err != nil {
			return err
		}
		_, err = ctx.Tx(node, pkt, nice, fileSize, minSize, reader)
		sds := SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
			"size": strconv.FormatInt(fileSize, 10),
		}
		if err == nil {
			ctx.LogI("tx", sds, "sent")
		} else {
			sds["err"] = err
			ctx.LogE("tx", sds, "sent")
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
		)
		sds := SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  path,
			"size": strconv.FormatInt(sizeToSend, 10),
		}
		if err == nil {
			ctx.LogI("tx", sds, "sent")
		} else {
			sds["err"] = err
			ctx.LogE("tx", sds, "sent")
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
	_, err = ctx.Tx(node, pkt, nice, metaPktSize, minSize, &metaBuf)
	sds := SDS{
		"type": "file",
		"node": node.Id,
		"nice": strconv.Itoa(int(nice)),
		"src":  srcPath,
		"dst":  path,
		"size": strconv.FormatInt(metaPktSize, 10),
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		sds["err"] = err
		ctx.LogE("tx", sds, "sent")
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
	_, err = ctx.Tx(node, pkt, nice, size, minSize, src)
	sds := SDS{
		"type":      "freq",
		"node":      node.Id,
		"nice":      strconv.Itoa(int(nice)),
		"replynice": strconv.Itoa(int(replyNice)),
		"src":       srcPath,
		"dst":       dstPath,
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		sds["err"] = err
		ctx.LogE("tx", sds, "sent")
	}
	return err
}

func (ctx *Ctx) TxExec(
	node *Node,
	nice, replyNice uint8,
	handle string,
	args []string,
	body []byte,
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
	compressor, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return err
	}
	if _, err = io.Copy(compressor, bytes.NewReader(body)); err != nil {
		return err
	}
	compressor.Close()
	size := int64(compressed.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, &compressed)
	sds := SDS{
		"type":      "exec",
		"node":      node.Id,
		"nice":      strconv.Itoa(int(nice)),
		"replynice": strconv.Itoa(int(replyNice)),
		"dst":       strings.Join(append([]string{handle}, args...), " "),
		"size":      strconv.FormatInt(size, 10),
	}
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		sds["err"] = err
		ctx.LogE("tx", sds, "sent")
	}
	return err
}

func (ctx *Ctx) TxTrns(node *Node, nice uint8, size int64, src io.Reader) error {
	sds := SDS{
		"type": "trns",
		"node": node.Id,
		"nice": strconv.Itoa(int(nice)),
		"size": strconv.FormatInt(size, 10),
	}
	ctx.LogD("tx", sds, "taken")
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return err
	}
	if _, err = io.Copy(tmp.W, src); err != nil {
		return err
	}
	nodePath := filepath.Join(ctx.Spool, node.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	if err == nil {
		ctx.LogI("tx", sds, "sent")
	} else {
		sds["err"] = err
		ctx.LogI("tx", sds, "sent")
	}
	os.Symlink(nodePath, filepath.Join(ctx.Spool, node.Name))
	return err
}
