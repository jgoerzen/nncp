/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

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
	"io"
	"log"

	"golang.org/x/crypto/blake2b"
)

func Check(src io.Reader, checksum []byte) (bool, error) {
	hsh, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err = io.Copy(hsh, bufio.NewReader(src)); err != nil {
		return false, err
	}
	return bytes.Compare(hsh.Sum(nil), checksum) == 0, nil
}

func (ctx *Ctx) checkXx(nodeId *NodeId, xx TRxTx) bool {
	isBad := false
	for job := range ctx.Jobs(nodeId, xx) {
		sds := SDS{
			"xx":   string(xx),
			"node": nodeId,
			"pkt":  ToBase32(job.HshValue[:]),
		}
		ctx.LogP("check", sds, "")
		gut, err := Check(job.Fd, job.HshValue[:])
		job.Fd.Close()
		if err != nil {
			ctx.LogE("check", SdsAdd(sds, SDS{"err": err}), "")
			return false
		}
		if !gut {
			isBad = true
			ctx.LogE("check", sds, "bad")
		}
	}
	return isBad
}

func (ctx *Ctx) Check(nodeId *NodeId) bool {
	return ctx.checkXx(nodeId, TRx) || ctx.checkXx(nodeId, TTx)
}
