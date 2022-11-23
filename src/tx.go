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

package nncp

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
)

const (
	MaxFileSize = 1 << 62

	TarBlockSize = 512
	TarExt       = ".tar"
)

type PktEncWriteResult struct {
	pktEncRaw []byte
	size      int64
	err       error
}

func (ctx *Ctx) Tx(
	node *Node,
	pkt *Pkt,
	nice uint8,
	srcSize, minSize, maxSize int64,
	src io.Reader,
	pktName string,
	areaId *AreaId,
) (*Node, int64, string, error) {
	var area *Area
	if areaId != nil {
		area = ctx.AreaId2Area[*areaId]
		if area.Prv == nil {
			return nil, 0, "", errors.New("area has no encryption keys")
		}
	}
	hops := make([]*Node, 0, 1+len(node.Via))
	hops = append(hops, node)
	lastNode := node
	for i := len(node.Via); i > 0; i-- {
		lastNode = ctx.Neigh[*node.Via[i-1]]
		hops = append(hops, lastNode)
	}
	wrappers := len(hops)
	if area != nil {
		wrappers++
	}
	var expectedSize int64
	if srcSize > 0 {
		expectedSize = srcSize + PktOverhead
		expectedSize += sizePadCalc(expectedSize, minSize, wrappers)
		expectedSize = PktEncOverhead + sizeWithTags(expectedSize)
		if maxSize != 0 && expectedSize > maxSize {
			return nil, 0, "", TooBig
		}
		if !ctx.IsEnoughSpace(expectedSize) {
			return nil, 0, "", errors.New("is not enough space")
		}
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return nil, 0, "", err
	}

	results := make(chan PktEncWriteResult)
	pipeR, pipeW := io.Pipe()
	var pipeRPrev io.Reader
	if area == nil {
		go func(src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", LEs{
				{"Node", hops[0].Id},
				{"Nice", int(nice)},
				{"Size", expectedSize},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Tx packet to %s (source %s) nice: %s",
					ctx.NodeName(hops[0].Id),
					humanize.IBytes(uint64(expectedSize)),
					NicenessFmt(nice),
				)
			})
			pktEncRaw, size, err := PktEncWrite(
				ctx.Self, hops[0], pkt, nice, minSize, maxSize, wrappers, src, dst,
			)
			results <- PktEncWriteResult{pktEncRaw, size, err}
			dst.Close()
		}(src, pipeW)
	} else {
		go func(src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", LEs{
				{"Area", area.Id},
				{"Nice", int(nice)},
				{"Size", expectedSize},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Tx area packet to %s (source %s) nice: %s",
					ctx.AreaName(areaId),
					humanize.IBytes(uint64(expectedSize)),
					NicenessFmt(nice),
				)
			})
			areaNode := Node{Id: new(NodeId), ExchPub: new([32]byte)}
			copy(areaNode.Id[:], area.Id[:])
			copy(areaNode.ExchPub[:], area.Pub[:])
			pktEncRaw, size, err := PktEncWrite(
				ctx.Self, &areaNode, pkt, nice, 0, maxSize, 0, src, dst,
			)
			results <- PktEncWriteResult{pktEncRaw, size, err}
			dst.Close()
		}(src, pipeW)
		pipeRPrev = pipeR
		pipeR, pipeW = io.Pipe()
		go func(src io.Reader, dst io.WriteCloser) {
			pktArea, err := NewPkt(PktTypeArea, 0, area.Id[:])
			if err != nil {
				panic(err)
			}
			ctx.LogD("tx", LEs{
				{"Node", hops[0].Id},
				{"Nice", int(nice)},
				{"Size", expectedSize},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Tx packet to %s (source %s) nice: %s",
					ctx.NodeName(hops[0].Id),
					humanize.IBytes(uint64(expectedSize)),
					NicenessFmt(nice),
				)
			})
			pktEncRaw, size, err := PktEncWrite(
				ctx.Self, hops[0], pktArea, nice, minSize, maxSize, wrappers, src, dst,
			)
			results <- PktEncWriteResult{pktEncRaw, size, err}
			dst.Close()
		}(pipeRPrev, pipeW)
	}
	for i := 1; i < len(hops); i++ {
		pktTrns, err := NewPkt(PktTypeTrns, 0, hops[i-1].Id[:])
		if err != nil {
			panic(err)
		}
		pipeRPrev = pipeR
		pipeR, pipeW = io.Pipe()
		go func(node *Node, pkt *Pkt, src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", LEs{
				{"Node", node.Id},
				{"Nice", int(nice)},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Tx trns packet to %s nice: %s",
					ctx.NodeName(node.Id),
					NicenessFmt(nice),
				)
			})
			pktEncRaw, size, err := PktEncWrite(
				ctx.Self, node, pkt, nice, 0, MaxFileSize, 0, src, dst,
			)
			results <- PktEncWriteResult{pktEncRaw, size, err}
			dst.Close()
		}(hops[i], pktTrns, pipeRPrev, pipeW)
	}
	go func() {
		_, err := CopyProgressed(
			tmp.W, pipeR, "Tx",
			LEs{{"Pkt", pktName}, {"FullSize", expectedSize}},
			ctx.ShowPrgrs,
		)
		results <- PktEncWriteResult{err: err}
	}()
	var pktEncRaw []byte
	var pktEncMsg []byte
	var payloadSize int64
	if area != nil {
		r := <-results
		payloadSize = r.size
		pktEncMsg = r.pktEncRaw
		wrappers--
	}
	for i := 0; i <= wrappers; i++ {
		r := <-results
		if r.err != nil {
			tmp.Fd.Close()
			return nil, 0, "", r.err
		}
		if r.pktEncRaw != nil {
			pktEncRaw = r.pktEncRaw
			if payloadSize == 0 {
				payloadSize = r.size
			}
		}
	}
	nodePath := filepath.Join(ctx.Spool, lastNode.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	os.Symlink(nodePath, filepath.Join(ctx.Spool, lastNode.Name))
	if err != nil {
		return lastNode, 0, "", err
	}
	if ctx.HdrUsage {
		ctx.HdrWrite(pktEncRaw, filepath.Join(nodePath, string(TTx), tmp.Checksum()))
	}
	if area != nil {
		msgHashRaw := blake2b.Sum256(pktEncMsg)
		msgHash := Base32Codec.EncodeToString(msgHashRaw[:])
		seenDir := filepath.Join(
			ctx.Spool, ctx.SelfId.String(), AreaDir, areaId.String(),
		)
		seenPath := filepath.Join(seenDir, msgHash)
		les := LEs{
			{"Node", node.Id},
			{"Nice", int(nice)},
			{"Size", expectedSize},
			{"Area", areaId},
			{"AreaMsg", msgHash},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"Tx area packet to %s (source %s) nice: %s, area %s: %s",
				ctx.NodeName(node.Id),
				humanize.IBytes(uint64(expectedSize)),
				NicenessFmt(nice),
				area.Name,
				msgHash,
			)
		}
		if err = ensureDir(seenDir); err != nil {
			ctx.LogE("tx-mkdir", les, err, logMsg)
			return lastNode, 0, "", err
		}
		if fd, err := os.Create(seenPath); err == nil {
			fd.Close()
			if err = DirSync(seenDir); err != nil {
				ctx.LogE("tx-dirsync", les, err, logMsg)
				return lastNode, 0, "", err
			}
		}
		ctx.LogI("tx-area", les, logMsg)
	}
	return lastNode, payloadSize, tmp.Checksum(), err
}

type DummyCloser struct{}

func (dc DummyCloser) Close() error { return nil }

func prepareTxFile(srcPath string) (
	reader io.Reader,
	closer io.Closer,
	srcSize int64,
	archived bool,
	rerr error,
) {
	if srcPath == "-" {
		reader = os.Stdin
		closer = os.Stdin
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
		reader = src
		closer = src
		srcSize = srcStat.Size()
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
		if info.Mode().IsDir() {
			// directory header, PAX record header+contents
			srcSize += TarBlockSize + 2*TarBlockSize
			dirs = append(dirs, einfo{path: path, modTime: info.ModTime()})
		} else if info.Mode().IsRegular() {
			// file header, PAX record header+contents, file content
			srcSize += TarBlockSize + 2*TarBlockSize + info.Size()
			if n := info.Size() % TarBlockSize; n != 0 {
				srcSize += TarBlockSize - n // padding
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
	srcSize += 2 * TarBlockSize // termination block

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
				fd.Close()
				return w.CloseWithError(err)
			}
			if _, err = io.Copy(
				tarWr, bufio.NewReaderSize(fd, MTHBlockSize),
			); err != nil {
				fd.Close()
				return w.CloseWithError(err)
			}
			fd.Close()
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
	chunkSize, minSize, maxSize int64,
	areaId *AreaId,
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
	reader, closer, srcSize, archived, err := prepareTxFile(srcPath)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		return err
	}
	if archived && !dstPathSpecified {
		dstPath += TarExt
	}

	if chunkSize == 0 || (srcSize > 0 && srcSize <= chunkSize) {
		pkt, err := NewPkt(PktTypeFile, nice, []byte(dstPath))
		if err != nil {
			return err
		}
		_, finalSize, pktName, err := ctx.Tx(
			node, pkt, nice,
			srcSize, minSize, maxSize,
			bufio.NewReaderSize(reader, MTHBlockSize), dstPath, areaId,
		)
		les := LEs{
			{"Type", "file"},
			{"Node", node.Id},
			{"Nice", int(nice)},
			{"Src", srcPath},
			{"Dst", dstPath},
			{"Size", finalSize},
			{"Pkt", pktName},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"File %s (%s) is sent to %s:%s",
				srcPath,
				humanize.IBytes(uint64(finalSize)),
				ctx.NodeName(node.Id),
				dstPath,
			)
		}
		if err == nil {
			ctx.LogI("tx", les, logMsg)
		} else {
			ctx.LogE("tx", les, err, logMsg)
		}
		return err
	}

	br := bufio.NewReaderSize(reader, MTHBlockSize)
	var sizeFull int64
	var chunkNum int
	checksums := [][MTHSize]byte{}
	for {
		lr := io.LimitReader(br, chunkSize)
		path := dstPath + ChunkedSuffixPart + strconv.Itoa(chunkNum)
		pkt, err := NewPkt(PktTypeFile, nice, []byte(path))
		if err != nil {
			return err
		}
		hsh := MTHNew(0, 0)
		_, size, pktName, err := ctx.Tx(
			node, pkt, nice,
			0, minSize, maxSize,
			io.TeeReader(lr, hsh),
			path, areaId,
		)

		les := LEs{
			{"Type", "file"},
			{"Node", node.Id},
			{"Nice", int(nice)},
			{"Src", srcPath},
			{"Dst", path},
			{"Size", size},
			{"Pkt", pktName},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"File %s (%s) is sent to %s:%s",
				srcPath,
				humanize.IBytes(uint64(size)),
				ctx.NodeName(node.Id),
				path,
			)
		}
		if err == nil {
			ctx.LogI("tx", les, logMsg)
		} else {
			ctx.LogE("tx", les, err, logMsg)
			return err
		}

		sizeFull += size - PktOverhead
		var checksum [MTHSize]byte
		hsh.Sum(checksum[:0])
		checksums = append(checksums, checksum)
		chunkNum++
		if size < chunkSize {
			break
		}
		if _, err = br.Peek(1); err != nil {
			break
		}
	}

	metaPkt := ChunkedMeta{
		Magic:     MagicNNCPMv2.B,
		FileSize:  uint64(sizeFull),
		ChunkSize: uint64(chunkSize),
		Checksums: checksums,
	}
	var buf bytes.Buffer
	_, err = xdr.Marshal(&buf, metaPkt)
	if err != nil {
		return err
	}
	path := dstPath + ChunkedSuffixMeta
	pkt, err := NewPkt(PktTypeFile, nice, []byte(path))
	if err != nil {
		return err
	}
	metaPktSize := int64(buf.Len())
	_, _, pktName, err := ctx.Tx(
		node,
		pkt,
		nice,
		metaPktSize, minSize, maxSize,
		&buf, path, areaId,
	)
	les := LEs{
		{"Type", "file"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"Src", srcPath},
		{"Dst", path},
		{"Size", metaPktSize},
		{"Pkt", pktName},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"File %s (%s) is sent to %s:%s",
			srcPath,
			humanize.IBytes(uint64(metaPktSize)),
			ctx.NodeName(node.Id),
			path,
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxFreq(
	node *Node,
	nice, replyNice uint8,
	srcPath, dstPath string,
	minSize int64,
) error {
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
	_, _, pktName, err := ctx.Tx(
		node, pkt, nice, size, minSize, MaxFileSize, src, srcPath, nil,
	)
	les := LEs{
		{"Type", "freq"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"ReplyNice", int(replyNice)},
		{"Src", srcPath},
		{"Dst", dstPath},
		{"Pkt", pktName},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"File request from %s:%s to %s is sent",
			ctx.NodeName(node.Id), srcPath,
			dstPath,
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxExec(
	node *Node,
	nice, replyNice uint8,
	handle string,
	args []string,
	in io.Reader,
	minSize int64, maxSize int64,
	noCompress bool,
	areaId *AreaId,
) error {
	path := make([][]byte, 0, 1+len(args))
	path = append(path, []byte(handle))
	for _, arg := range args {
		path = append(path, []byte(arg))
	}
	pktType := PktTypeExec
	if noCompress {
		pktType = PktTypeExecFat
	}
	pkt, err := NewPkt(pktType, replyNice, bytes.Join(path, []byte{0}))
	if err != nil {
		return err
	}
	compressErr := make(chan error, 1)
	if !noCompress {
		pr, pw := io.Pipe()
		compressor, err := zstd.NewWriter(pw, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if err != nil {
			return err
		}
		go func(r io.Reader) {
			if _, err := io.Copy(compressor, r); err != nil {
				compressErr <- err
				return
			}
			compressErr <- compressor.Close()
			pw.Close()
		}(in)
		in = pr
	}
	_, size, pktName, err := ctx.Tx(
		node, pkt, nice, 0, minSize, maxSize, in, handle, areaId,
	)
	if !noCompress {
		e := <-compressErr
		if err == nil {
			err = e
		}
	}
	dst := strings.Join(append([]string{handle}, args...), " ")
	les := LEs{
		{"Type", "exec"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"ReplyNice", int(replyNice)},
		{"Dst", dst},
		{"Size", size},
		{"Pkt", pktName},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"Exec is sent to %s@%s (%s)",
			ctx.NodeName(node.Id), dst, humanize.IBytes(uint64(size)),
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxTrns(node *Node, nice uint8, size int64, src io.Reader) error {
	les := LEs{
		{"Type", "trns"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"Size", size},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"Transitional packet to %s (%s) (nice %s)",
			ctx.NodeName(node.Id),
			humanize.IBytes(uint64(size)),
			NicenessFmt(nice),
		)
	}
	ctx.LogD("tx", les, logMsg)
	if !ctx.IsEnoughSpace(size) {
		err := errors.New("is not enough space")
		ctx.LogE("tx", les, err, logMsg)
		return err
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return err
	}
	if _, err = CopyProgressed(
		tmp.W, src, "Tx trns",
		LEs{{"Pkt", node.Id.String()}, {"FullSize", size}},
		ctx.ShowPrgrs,
	); err != nil {
		return err
	}
	nodePath := filepath.Join(ctx.Spool, node.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogI("tx", append(les, LE{"Err", err}), logMsg)
	}
	os.Symlink(nodePath, filepath.Join(ctx.Spool, node.Name))
	return err
}

func (ctx *Ctx) TxACK(
	node *Node,
	nice uint8,
	hsh string,
	minSize int64,
) (pktName string, err error) {
	hshRaw, err := Base32Codec.DecodeString(hsh)
	if err != nil {
		return "", err
	}
	if len(hshRaw) != MTHSize {
		return "", errors.New("Invalid packet id size")
	}
	pkt, err := NewPkt(PktTypeACK, nice, []byte(hshRaw))
	if err != nil {
		return "", err
	}
	src := bytes.NewReader([]byte{})
	_, _, pktName, err = ctx.Tx(
		node, pkt, nice, 0, minSize, MaxFileSize, src, hsh, nil,
	)
	les := LEs{
		{"Type", "ack"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"Pkt", hsh},
		{"NewPkt", pktName},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf("ACK to %s of %s is sent", ctx.NodeName(node.Id), hsh)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return
}
