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
	"io"
	"testing"
	"testing/quick"

	"lukechampine.com/blake3"
)

func TestMTHSeqSymmetric(t *testing.T) {
	xof := blake3.New(32, nil).XOF()
	f := func(size uint32, offset uint32) bool {
		size %= 2 * 1024 * 1024
		data := make([]byte, int(size), int(size)+1)
		if _, err := io.ReadFull(xof, data); err != nil {
			panic(err)
		}
		offset = offset % size

		mth := MTHSeqNew(int64(size), 0)
		if _, err := io.Copy(mth, bytes.NewReader(data)); err != nil {
			panic(err)
		}
		hsh0 := mth.Sum(nil)

		mth = MTHSeqNew(int64(size), int64(offset))
		if _, err := io.Copy(mth, bytes.NewReader(data[int(offset):])); err != nil {
			panic(err)
		}
		if _, err := mth.PreaddFrom(bytes.NewReader(data), "", false); err != nil {
			panic(err)
		}
		if bytes.Compare(hsh0, mth.Sum(nil)) != 0 {
			return false
		}

		mth = MTHSeqNew(0, 0)
		mth.Write(data)
		if bytes.Compare(hsh0, mth.Sum(nil)) != 0 {
			return false
		}

		data = append(data, 0)
		mth = MTHSeqNew(int64(size)+1, 0)
		if _, err := io.Copy(mth, bytes.NewReader(data)); err != nil {
			panic(err)
		}
		hsh00 := mth.Sum(nil)
		if bytes.Compare(hsh0, hsh00) == 0 {
			return false
		}

		mth = MTHSeqNew(int64(size)+1, int64(offset))
		if _, err := io.Copy(mth, bytes.NewReader(data[int(offset):])); err != nil {
			panic(err)
		}
		if _, err := mth.PreaddFrom(bytes.NewReader(data), "", false); err != nil {
			panic(err)
		}
		if bytes.Compare(hsh00, mth.Sum(nil)) != 0 {
			return false
		}

		mth = MTHSeqNew(0, 0)
		mth.Write(data)
		if bytes.Compare(hsh00, mth.Sum(nil)) != 0 {
			return false
		}

		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMTHSeqAndFatEqual(t *testing.T) {
	xof := blake3.New(32, nil).XOF()
	f := func(size uint32, offset uint32) bool {
		size %= 10 * 1024 * 1024
		data := make([]byte, int(size), int(size)+1)
		if _, err := io.ReadFull(xof, data); err != nil {
			panic(err)
		}
		fat := MTHFatNew()
		if _, err := io.Copy(fat, bytes.NewReader(data)); err != nil {
			panic(err)
		}
		hshFat := fat.Sum(nil)
		seq := MTHSeqNew(int64(size), 0)
		if _, err := io.Copy(seq, bytes.NewReader(data)); err != nil {
			panic(err)
		}
		return bytes.Compare(hshFat, seq.Sum(nil)) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMTHNull(t *testing.T) {
	fat := MTHFatNew()
	if _, err := fat.Write(nil); err != nil {
		t.Error(err)
	}
	hshFat := fat.Sum(nil)

	seq := MTHSeqNew(0, 0)
	if _, err := seq.Write(nil); err != nil {
		t.Error(err)
	}
	if bytes.Compare(hshFat, seq.Sum(nil)) != 0 {
		t.FailNow()
	}
}
