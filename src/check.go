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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const NoCKSuffix = ".nock"

func Check(
	src io.Reader,
	size int64,
	checksum []byte,
	les LEs,
	showPrgrs bool,
) (bool, error) {
	hsh := MTHNew(size, 0)
	if _, err := CopyProgressed(
		hsh,
		bufio.NewReaderSize(src, MTHBlockSize),
		"check", les, showPrgrs,
	); err != nil {
		return false, err
	}
	return bytes.Compare(hsh.Sum(nil), checksum) == 0, nil
}

func (ctx *Ctx) checkXxIsBad(nodeId *NodeId, xx TRxTx) bool {
	isBad := false
	for job := range ctx.Jobs(nodeId, xx) {
		pktName := Base32Codec.EncodeToString(job.HshValue[:])
		les := LEs{
			{"XX", string(xx)},
			{"Node", nodeId},
			{"Pkt", pktName},
			{"FullSize", job.Size},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf("Checking: %s/%s/%s", nodeId, string(xx), pktName)
		}
		fd, err := os.Open(job.Path)
		if err != nil {
			ctx.LogE("checking", les, err, logMsg)
			return true
		}
		gut, err := Check(fd, job.Size, job.HshValue[:], les, ctx.ShowPrgrs)
		fd.Close()
		if err != nil {
			ctx.LogE("checking", les, err, logMsg)
			return true
		}
		if !gut {
			isBad = true
			ctx.LogE("checking", les, errors.New("bad"), logMsg)
		}
	}
	return isBad
}

func (ctx *Ctx) Check(nodeId *NodeId) bool {
	return !(ctx.checkXxIsBad(nodeId, TRx) || ctx.checkXxIsBad(nodeId, TTx))
}

func (ctx *Ctx) CheckNoCK(nodeId *NodeId, hshValue *[MTHSize]byte, mth MTH) (int64, error) {
	dirToSync := filepath.Join(ctx.Spool, nodeId.String(), string(TRx))
	pktName := Base32Codec.EncodeToString(hshValue[:])
	pktPath := filepath.Join(dirToSync, pktName)
	fd, err := os.Open(pktPath + NoCKSuffix)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	les := LEs{
		{"XX", string(TRx)},
		{"Node", nodeId},
		{"Pkt", pktName},
		{"FullSize", size},
	}
	var gut bool
	if mth == nil {
		gut, err = Check(fd, size, hshValue[:], les, ctx.ShowPrgrs)
	} else {
		if _, err = mth.PreaddFrom(
			bufio.NewReaderSize(fd, MTHBlockSize),
			pktName, ctx.ShowPrgrs,
		); err != nil {
			return 0, err
		}
		if bytes.Compare(mth.Sum(nil), hshValue[:]) == 0 {
			gut = true
		}
	}
	if err != nil || !gut {
		return 0, errors.New("checksum mismatch")
	}
	if err = os.Rename(pktPath+NoCKSuffix, pktPath); err != nil {
		return 0, err
	}
	if err = DirSync(dirToSync); err != nil {
		return size, err
	}
	if ctx.HdrUsage {
		if _, err = fd.Seek(0, io.SeekStart); err != nil {
			return size, err
		}
		_, pktEncRaw, err := ctx.HdrRead(fd)
		if err != nil {
			return size, err
		}
		ctx.HdrWrite(pktEncRaw, pktPath)
	}
	return size, err
}
