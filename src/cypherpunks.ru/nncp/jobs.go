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
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/davecgh/go-xdr/xdr2"
)

type TRxTx string

const (
	TRx TRxTx = "rx"
	TTx TRxTx = "tx"
)

type Job struct {
	PktEnc   *PktEnc
	Fd       *os.File
	Size     int64
	HshValue *[32]byte
}

func (ctx *Ctx) Jobs(nodeId *NodeId, xx TRxTx) chan Job {
	rxPath := filepath.Join(ctx.Spool, nodeId.String(), string(xx))
	jobs := make(chan Job, 16)
	go func() {
		defer close(jobs)
		dir, err := os.Open(rxPath)
		if err != nil {
			return
		}
		fis, err := dir.Readdir(0)
		dir.Close()
		if err != nil {
			return
		}
		for _, fi := range fis {
			hshValue, err := FromBase32(fi.Name())
			if err != nil {
				continue
			}
			fd, err := os.Open(filepath.Join(rxPath, fi.Name()))
			if err != nil {
				continue
			}
			var pktEnc PktEnc
			if _, err = xdr.Unmarshal(fd, &pktEnc); err != nil || pktEnc.Magic != MagicNNCPEv4 {
				fd.Close()
				continue
			}
			fd.Seek(0, io.SeekStart)
			ctx.LogD("jobs", SDS{
				"xx":   string(xx),
				"node": pktEnc.Sender,
				"name": fi.Name(),
				"nice": strconv.Itoa(int(pktEnc.Nice)),
				"size": strconv.FormatInt(fi.Size(), 10),
			}, "taken")
			job := Job{
				PktEnc:   &pktEnc,
				Fd:       fd,
				Size:     fi.Size(),
				HshValue: new([32]byte),
			}
			copy(job.HshValue[:], hshValue)
			jobs <- job
		}
	}()
	return jobs
}
