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
	"testing"
	"testing/quick"

	xdr "github.com/davecgh/go-xdr/xdr2"
)

func TestPktEncWrite(t *testing.T) {
	nodeOur, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	nodeTheir, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	f := func(
		path string,
		pathSize uint8,
		dataSize uint32,
		size, minSize uint16,
		wrappers uint8,
	) bool {
		dataSize %= 1 << 20
		data := make([]byte, dataSize)
		if _, err = io.ReadFull(rand.Reader, data); err != nil {
			panic(err)
		}
		var ct bytes.Buffer
		if len(path) > int(pathSize) {
			path = path[:int(pathSize)]
		}
		nice := uint8(123)
		pkt, err := NewPkt(PktTypeFile, nice, []byte(path))
		if err != nil {
			panic(err)
		}
		wrappers %= 8
		_, _, err = PktEncWrite(
			nodeOur,
			nodeTheir.Their(),
			pkt,
			nice,
			int64(minSize),
			MaxFileSize,
			int(wrappers),
			bytes.NewReader(data),
			&ct,
		)
		if err != nil {
			return false
		}
		var pktEnc PktEnc
		if _, err = xdr.Unmarshal(&ct, &pktEnc); err != nil {
			return false
		}
		if *pktEnc.Sender != *nodeOur.Id {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestPktEncRead(t *testing.T) {
	node1, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	node2, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	f := func(
		path string,
		pathSize uint8,
		dataSize uint32,
		minSize uint16,
		wrappers uint8,
	) bool {
		dataSize %= 1 << 20
		data := make([]byte, dataSize)
		if _, err = io.ReadFull(rand.Reader, data); err != nil {
			panic(err)
		}
		var ct bytes.Buffer
		if len(path) > int(pathSize) {
			path = path[:int(pathSize)]
		}
		nice := uint8(123)
		pkt, err := NewPkt(PktTypeFile, nice, []byte(path))
		if err != nil {
			panic(err)
		}
		wrappers %= 8
		_, _, err = PktEncWrite(
			node1,
			node2.Their(),
			pkt,
			nice,
			int64(minSize),
			MaxFileSize,
			int(wrappers),
			bytes.NewReader(data),
			&ct,
		)
		if err != nil {
			return false
		}
		var pt bytes.Buffer
		nodes := make(map[NodeId]*Node)
		nodes[*node1.Id] = node1.Their()
		_, node, sizeGot, err := PktEncRead(node2, nodes, &ct, &pt, true, nil)
		if err != nil {
			return false
		}
		if *node.Id != *node1.Id {
			return false
		}
		if sizeGot != int64(len(data)+int(PktOverhead)) {
			return false
		}
		var pktBuf bytes.Buffer
		xdr.Marshal(&pktBuf, &pkt)
		return bytes.Compare(pt.Bytes(), append(pktBuf.Bytes(), data...)) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
