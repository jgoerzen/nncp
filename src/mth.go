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
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"lukechampine.com/blake3"
)

const (
	MTHBlockSize = 128 * 1024
	MTHSize      = 32
)

var (
	MTHLeafKey = blake3.Sum256([]byte("NNCP MTH LEAF"))
	MTHNodeKey = blake3.Sum256([]byte("NNCP MTH NODE"))
)

type MTHSeqEnt struct {
	l int
	c int64
	h [MTHSize]byte
}

func (ent *MTHSeqEnt) String() string {
	return fmt.Sprintf("%03d\t%06d\t%s", ent.l, ent.c, hex.EncodeToString(ent.h[:]))
}

type MTHEventType string

const (
	MTHEventAdd    MTHEventType = "Add"
	MTHEventPreadd MTHEventType = "Pre"
	MTHEventFold   MTHEventType = "Fold"
)

type MTHEvent struct {
	Type MTHEventType
	Ent  *MTHSeqEnt
}

func (e MTHEvent) String() string {
	return fmt.Sprintf("%s\t%s", e.Type, e.Ent.String())
}

type MTH interface {
	hash.Hash
	PreaddFrom(r io.Reader, pktName string, showPrgrs bool) (int64, error)
	PreaddSize() int64
	Events() chan MTHEvent
}

type MTHSeq struct {
	hasherLeaf  *blake3.Hasher
	hasherNode  *blake3.Hasher
	hashes      []MTHSeqEnt
	buf         *bytes.Buffer
	events      chan MTHEvent
	ctr         int64
	size        int64
	prependSize int64
	toSkip      int64
	skipped     bool
	finished    bool
	pktName     string
}

func MTHSeqNew(size, offset int64) *MTHSeq {
	mth := MTHSeq{
		hasherLeaf: blake3.New(MTHSize, MTHLeafKey[:]),
		hasherNode: blake3.New(MTHSize, MTHNodeKey[:]),
		buf:        bytes.NewBuffer(make([]byte, 0, 2*MTHBlockSize)),
	}
	if size == 0 {
		return &mth
	}
	prepends := offset / MTHBlockSize
	toSkip := MTHBlockSize - (offset - prepends*MTHBlockSize)
	if toSkip == MTHBlockSize {
		toSkip = 0
	} else if toSkip > 0 {
		prepends++
	}
	prependSize := prepends * MTHBlockSize
	mth.ctr = prepends
	if prependSize > size {
		prependSize = size
	}
	if offset+toSkip > size {
		toSkip = size - offset
	}
	mth.size = size
	mth.prependSize = prependSize
	mth.toSkip = toSkip
	return &mth
}

func (mth *MTHSeq) Reset() { panic("not implemented") }

func (mth *MTHSeq) Size() int { return MTHSize }

func (mth *MTHSeq) BlockSize() int { return MTHBlockSize }

func (mth *MTHSeq) PreaddFrom(r io.Reader, pktName string, showPrgrs bool) (int64, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	if mth.buf.Len() > 0 {
		if _, err := mth.hasherLeaf.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			panic(err)
		}
		mth.leafAdd()
		mth.fold()
	}
	prevHashes := mth.hashes
	mth.hashes = nil
	prevCtr := mth.ctr
	mth.ctr = 0
	lr := io.LimitedReader{R: r, N: mth.prependSize}
	les := LEs{{"Pkt", pktName}, {"FullSize", mth.prependSize}}
	n, err := CopyProgressed(mth, &lr, "prehash", les, showPrgrs)
	for _, ent := range prevHashes {
		mth.hashes = append(mth.hashes, ent)
		mth.fold()
	}
	if mth.buf.Len() > 0 {
		mth.ctr = prevCtr - 1
	} else {
		mth.ctr = prevCtr
	}
	return n, err
}

func (mth *MTHSeq) Events() chan MTHEvent {
	mth.events = make(chan MTHEvent)
	return mth.events
}

func (mth *MTHSeq) PreaddSize() int64 { return mth.prependSize }

func (mth *MTHSeq) leafAdd() {
	ent := MTHSeqEnt{c: mth.ctr}
	mth.hasherLeaf.Sum(ent.h[:0])
	mth.hasherLeaf.Reset()
	mth.hashes = append(mth.hashes, ent)
	mth.ctr++
	if mth.events != nil {
		mth.events <- MTHEvent{MTHEventAdd, &ent}
	}
}

func (mth *MTHSeq) fold() {
	for len(mth.hashes) >= 2 {
		hlen := len(mth.hashes)
		end1 := &mth.hashes[hlen-2]
		end0 := &mth.hashes[hlen-1]
		if end1.c%2 == 1 {
			break
		}
		if end1.l != end0.l {
			break
		}
		if _, err := mth.hasherNode.Write(end1.h[:]); err != nil {
			panic(err)
		}
		if _, err := mth.hasherNode.Write(end0.h[:]); err != nil {
			panic(err)
		}
		mth.hashes = mth.hashes[:hlen-1]
		end1.l++
		end1.c /= 2
		mth.hasherNode.Sum(end1.h[:0])
		mth.hasherNode.Reset()
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventFold, end1}
		}
	}
}

func (mth *MTHSeq) Write(data []byte) (int, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	n, err := mth.buf.Write(data)
	if err != nil {
		return n, err
	}
	if mth.toSkip > 0 {
		if int64(mth.buf.Len()) < mth.toSkip {
			return n, err
		}
		mth.buf.Next(int(mth.toSkip))
		mth.toSkip = 0
	}
	for mth.buf.Len() >= MTHBlockSize {
		if _, err = mth.hasherLeaf.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			return n, err
		}
		mth.leafAdd()
		mth.fold()
	}
	return n, err
}

func (mth *MTHSeq) Sum(b []byte) []byte {
	if mth.finished {
		return append(b, mth.hashes[0].h[:]...)
	}
	if mth.buf.Len() > 0 {
		if _, err := mth.hasherLeaf.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			panic(err)
		}
		mth.leafAdd()
		mth.fold()
	}
	switch mth.ctr {
	case 0:
		if _, err := mth.hasherLeaf.Write(nil); err != nil {
			panic(err)
		}
		mth.leafAdd()
		fallthrough
	case 1:
		ent := MTHSeqEnt{c: 1}
		copy(ent.h[:], mth.hashes[0].h[:])
		mth.ctr = 2
		mth.hashes = append(mth.hashes, ent)
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAdd, &ent}
		}
		mth.fold()
	}
	for len(mth.hashes) >= 2 {
		hlen := len(mth.hashes)
		end1 := &mth.hashes[hlen-2]
		end0 := &mth.hashes[hlen-1]
		end0.l = end1.l
		end0.c = end1.c + 1
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAdd, end0}
		}
		mth.fold()
	}
	mth.finished = true
	if mth.events != nil {
		close(mth.events)
	}
	return append(b, mth.hashes[0].h[:]...)
}

func MTHNew(size, offset int64) MTH {
	return MTHSeqNew(size, offset)
}

// Some kind of reference implementation (fat, because eats memory)

type MTHFat struct {
	hasher *blake3.Hasher
	hashes [][MTHSize]byte
	buf    *bytes.Buffer
	events chan MTHEvent
}

func MTHFatNew() *MTHFat {
	return &MTHFat{
		hasher: blake3.New(MTHSize, MTHLeafKey[:]),
		buf:    bytes.NewBuffer(make([]byte, 0, 2*MTHBlockSize)),
	}
}

func (mth *MTHFat) Events() chan MTHEvent {
	mth.events = make(chan MTHEvent)
	return mth.events
}

func (mth *MTHFat) Write(data []byte) (int, error) {
	n, err := mth.buf.Write(data)
	if err != nil {
		return n, err
	}
	for mth.buf.Len() >= MTHBlockSize {
		if _, err = mth.hasher.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			return n, err
		}
		h := new([MTHSize]byte)
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAdd,
				&MTHSeqEnt{
					0, int64(len(mth.hashes) - 1),
					mth.hashes[len(mth.hashes)-1],
				},
			}
		}
	}
	return n, err
}

func (mth *MTHFat) Sum(b []byte) []byte {
	if mth.buf.Len() > 0 {
		b := mth.buf.Next(MTHBlockSize)
		if _, err := mth.hasher.Write(b); err != nil {
			panic(err)
		}
		h := new([MTHSize]byte)
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAdd,
				&MTHSeqEnt{
					0, int64(len(mth.hashes) - 1),
					mth.hashes[len(mth.hashes)-1],
				},
			}
		}
	}
	switch len(mth.hashes) {
	case 0:
		h := new([MTHSize]byte)
		if _, err := mth.hasher.Write(nil); err != nil {
			panic(err)
		}
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAdd, &MTHSeqEnt{0, 0, mth.hashes[0]}}
		}
		fallthrough
	case 1:
		mth.hashes = append(mth.hashes, mth.hashes[0])
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAdd, &MTHSeqEnt{0, 1, mth.hashes[1]}}
		}
	}
	mth.hasher = blake3.New(MTHSize, MTHNodeKey[:])
	level := 1
	for len(mth.hashes) != 1 {
		hashesUp := make([][MTHSize]byte, 0, 1+len(mth.hashes)/2)
		pairs := (len(mth.hashes) / 2) * 2
		for i := 0; i < pairs; i += 2 {
			if _, err := mth.hasher.Write(mth.hashes[i][:]); err != nil {
				panic(err)
			}
			if _, err := mth.hasher.Write(mth.hashes[i+1][:]); err != nil {
				panic(err)
			}
			h := new([MTHSize]byte)
			mth.hasher.Sum(h[:0])
			mth.hasher.Reset()
			hashesUp = append(hashesUp, *h)
			if mth.events != nil {
				mth.events <- MTHEvent{
					MTHEventFold,
					&MTHSeqEnt{
						level, int64(len(hashesUp) - 1),
						hashesUp[len(hashesUp)-1],
					},
				}
			}
		}
		if len(mth.hashes)%2 == 1 {
			hashesUp = append(hashesUp, mth.hashes[len(mth.hashes)-1])
			if mth.events != nil {
				mth.events <- MTHEvent{
					MTHEventAdd,
					&MTHSeqEnt{
						level, int64(len(hashesUp) - 1),
						hashesUp[len(hashesUp)-1],
					},
				}
			}
		}
		mth.hashes = hashesUp
		level++
	}
	if mth.events != nil {
		close(mth.events)
	}
	return append(b, mth.hashes[0][:]...)
}
