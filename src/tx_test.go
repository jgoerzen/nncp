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
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"testing/quick"

	xdr "github.com/davecgh/go-xdr/xdr2"
)

func TestTx(t *testing.T) {
	f := func(
		hops uint8,
		pathSrc string,
		dataSize uint32,
		nice, replyNice uint8,
		minSize uint32,
	) bool {
		dataSize %= 1 << 20
		data := make([]byte, dataSize)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			panic(err)
		}
		minSize %= 1 << 20
		if len(pathSrc) > int(MaxPathSize) {
			pathSrc = pathSrc[:MaxPathSize]
		}
		hops = hops % 4
		spool, err := ioutil.TempDir("", "testtx")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			panic(err)
		}
		nodeTgtOur, err := NewNodeGenerate()
		if err != nil {
			panic(err)
		}
		nodeTgt := nodeTgtOur.Their()
		ctx := Ctx{
			Spool:   spool,
			LogPath: path.Join(spool, "log.log"),
			Debug:   true,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node, hops),
			Alias:   make(map[string]*NodeId),
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		ctx.Neigh[*nodeTgt.Id] = nodeTgt
		privates := make(map[NodeId]*NodeOur, int(hops)+1)
		privates[*nodeTgt.Id] = nodeTgtOur
		privates[*nodeOur.Id] = nodeOur
		for i := uint8(0); i < hops; i++ {
			node, err := NewNodeGenerate()
			if err != nil {
				panic(err)
			}
			ctx.Neigh[*node.Id] = node.Their()
			privates[*node.Id] = node
			nodeTgt.Via = append(nodeTgt.Via, node.Id)
		}
		pkt, err := NewPkt(PktTypeExec, replyNice, []byte(pathSrc))
		src := bytes.NewReader(data)
		dstNode, _, _, err := ctx.Tx(
			nodeTgt,
			pkt,
			123,
			int64(src.Len()),
			int64(minSize),
			MaxFileSize,
			src,
			"pktName",
			nil,
		)
		if err != nil {
			return false
		}

		sentJobs := make([]Job, 0, 1)
		for txJob := range ctx.Jobs(dstNode.Id, TTx) {
			sentJobs = append(sentJobs, txJob)
		}
		if len(sentJobs) != 1 {
			return false
		}
		txJob := sentJobs[0]
		fd, err := os.Open(txJob.Path)
		if err != nil {
			panic(err)
		}
		defer fd.Close()
		var bufR bytes.Buffer
		if _, err = io.Copy(&bufR, fd); err != nil {
			panic(err)
		}
		var bufW bytes.Buffer
		vias := append(nodeTgt.Via, nodeTgt.Id)
		for i, hopId := range vias {
			hopOur := privates[*hopId]
			_, foundNode, _, err := PktEncRead(
				hopOur, ctx.Neigh, &bufR, &bufW, true, nil,
			)
			if err != nil {
				return false
			}
			if *foundNode.Id != *nodeOur.Id {
				return false
			}
			bufR, bufW = bufW, bufR
			bufW.Reset()
			var pkt Pkt
			if _, err = xdr.Unmarshal(&bufR, &pkt); err != nil {
				return false
			}
			if *hopId == *nodeTgt.Id {
				if pkt.Type != PktTypeExec {
					return false
				}
				if pkt.Nice != replyNice {
					return false
				}
				if !bytes.HasPrefix(pkt.Path[:], []byte(pathSrc)) {
					return false
				}
				if bytes.Compare(bufR.Bytes(), []byte(data)) != 0 {
					return false
				}
			} else {
				if pkt.Type != PktTypeTrns {
					return false
				}
				if bytes.Compare(pkt.Path[:MTHSize], vias[i+1][:]) != 0 {
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
