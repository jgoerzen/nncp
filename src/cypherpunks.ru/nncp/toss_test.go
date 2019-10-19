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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/quick"

	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
)

var (
	TDebug bool = false
)

func dirFiles(path string) []string {
	dir, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(0)
	if err != nil {
		panic(err)
	}
	return names
}

func TestTossExec(t *testing.T) {
	f := func(replyNice uint8, handleRaw uint32, recipients [16]uint8) bool {
		handle := strconv.Itoa(int(handleRaw))
		for i, recipient := range recipients {
			recipients[i] = recipient % 8
		}
		spool, err := ioutil.TempDir("", "testtoss")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			t.Error(err)
			return false
		}
		ctx := Ctx{
			Spool:   spool,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node),
			Alias:   make(map[string]*NodeId),
			LogPath: filepath.Join(spool, "log.log"),
			Debug:   TDebug,
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		privates := make(map[uint8]*NodeOur)
		for _, recipient := range recipients {
			if _, exists := privates[recipient]; exists {
				continue
			}
			our, err := NewNodeGenerate()
			if err != nil {
				t.Error(err)
				return false
			}
			privates[recipient] = our
			ctx.Neigh[*our.Id] = our.Their()
		}
		for _, recipient := range recipients {
			if err := ctx.TxExec(
				ctx.Neigh[*privates[recipient].Id],
				DefaultNiceExec,
				replyNice,
				handle,
				[]string{"arg0", "arg1"},
				[]byte("BODY\n"),
				1<<15,
			); err != nil {
				t.Error(err)
				return false
			}
		}
		for _, recipient := range recipients {
			ctx.Self = privates[recipient]
			rxPath := filepath.Join(spool, ctx.Self.Id.String(), string(TRx))
			os.Rename(filepath.Join(spool, ctx.Self.Id.String(), string(TTx)), rxPath)
			if len(dirFiles(rxPath)) == 0 {
				continue
			}
			ctx.Toss(ctx.Self.Id, DefaultNiceExec-1, false, false, false, false, false, false)
			if len(dirFiles(rxPath)) == 0 {
				return false
			}
			ctx.Neigh[*nodeOur.Id].Exec = make(map[string][]string)
			ctx.Neigh[*nodeOur.Id].Exec[handle] = []string{"/bin/sh", "-c", "false"}
			ctx.Toss(ctx.Self.Id, DefaultNiceExec, false, false, false, false, false, false)
			if len(dirFiles(rxPath)) == 0 {
				return false
			}
			ctx.Neigh[*nodeOur.Id].Exec[handle] = []string{
				"/bin/sh", "-c",
				fmt.Sprintf(
					"echo $NNCP_NICE $0 $1 >> %s ; cat >> %s",
					filepath.Join(spool, "mbox"),
					filepath.Join(spool, "mbox"),
				),
			}
			ctx.Toss(ctx.Self.Id, DefaultNiceExec, false, false, false, false, false, false)
			if len(dirFiles(rxPath)) != 0 {
				return false
			}
		}
		mbox, err := ioutil.ReadFile(filepath.Join(spool, "mbox"))
		if err != nil {
			return false
		}
		expected := make([]byte, 0, 16)
		for i := 0; i < 16; i++ {
			expected = append(
				expected,
				[]byte(fmt.Sprintf("%d arg0 arg1\n", replyNice))...,
			)
			expected = append(expected, []byte("BODY\n")...)
		}
		return bytes.Compare(mbox, expected) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTossFile(t *testing.T) {
	f := func(fileSizes []uint8) bool {
		if len(fileSizes) == 0 {
			return true
		}
		files := make(map[string][]byte)
		for i, fileSize := range fileSizes {
			data := make([]byte, fileSize)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				panic(err)
			}
			files[strconv.Itoa(i)] = data
		}
		spool, err := ioutil.TempDir("", "testtoss")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			t.Error(err)
			return false
		}
		ctx := Ctx{
			Spool:   spool,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node),
			Alias:   make(map[string]*NodeId),
			LogPath: filepath.Join(spool, "log.log"),
			Debug:   TDebug,
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		incomingPath := filepath.Join(spool, "incoming")
		for _, fileData := range files {
			checksum := blake2b.Sum256(fileData)
			fileName := ToBase32(checksum[:])
			src := filepath.Join(spool, fileName)
			if err := ioutil.WriteFile(src, fileData, os.FileMode(0600)); err != nil {
				panic(err)
			}
			if err := ctx.TxFile(
				ctx.Neigh[*nodeOur.Id],
				DefaultNiceFile,
				src,
				fileName,
				1<<15,
			); err != nil {
				t.Error(err)
				return false
			}
		}
		rxPath := filepath.Join(spool, ctx.Self.Id.String(), string(TRx))
		os.Rename(filepath.Join(spool, ctx.Self.Id.String(), string(TTx)), rxPath)
		ctx.Toss(ctx.Self.Id, DefaultNiceFile, false, false, false, false, false, false)
		if len(dirFiles(rxPath)) == 0 {
			return false
		}
		ctx.Neigh[*nodeOur.Id].Incoming = &incomingPath
		ctx.Toss(ctx.Self.Id, DefaultNiceFile, false, false, false, false, false, false)
		if len(dirFiles(rxPath)) != 0 {
			return false
		}
		for _, fileData := range files {
			checksum := blake2b.Sum256(fileData)
			fileName := ToBase32(checksum[:])
			data, err := ioutil.ReadFile(filepath.Join(incomingPath, fileName))
			if err != nil {
				panic(err)
			}
			if bytes.Compare(data, fileData) != 0 {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTossFileSameName(t *testing.T) {
	f := func(filesRaw uint8) bool {
		files := int(filesRaw)%8 + 1
		spool, err := ioutil.TempDir("", "testtoss")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			t.Error(err)
			return false
		}
		ctx := Ctx{
			Spool:   spool,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node),
			Alias:   make(map[string]*NodeId),
			LogPath: filepath.Join(spool, "log.log"),
			Debug:   TDebug,
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		srcPath := filepath.Join(spool, "junk")
		if err = ioutil.WriteFile(
			srcPath,
			[]byte("doesnotmatter"),
			os.FileMode(0600),
		); err != nil {
			t.Error(err)
			return false
		}
		incomingPath := filepath.Join(spool, "incoming")
		for i := 0; i < files; i++ {
			if err := ctx.TxFile(
				ctx.Neigh[*nodeOur.Id],
				DefaultNiceFile,
				srcPath,
				"samefile",
				1<<15,
			); err != nil {
				t.Error(err)
				return false
			}
		}
		rxPath := filepath.Join(spool, ctx.Self.Id.String(), string(TRx))
		os.Rename(filepath.Join(spool, ctx.Self.Id.String(), string(TTx)), rxPath)
		ctx.Neigh[*nodeOur.Id].Incoming = &incomingPath
		ctx.Toss(ctx.Self.Id, DefaultNiceFile, false, false, false, false, false, false)
		expected := make(map[string]struct{})
		expected["samefile"] = struct{}{}
		for i := 0; i < files-1; i++ {
			expected["samefile"+strconv.Itoa(i)] = struct{}{}
		}
		for _, filename := range dirFiles(incomingPath) {
			if _, exists := expected[filename]; !exists {
				return false
			}
			delete(expected, filename)
		}
		if len(expected) != 0 {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTossFreq(t *testing.T) {
	f := func(fileSizes []uint8, replyNice uint8) bool {
		if len(fileSizes) == 0 {
			return true
		}
		spool, err := ioutil.TempDir("", "testtoss")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			t.Error(err)
			return false
		}
		ctx := Ctx{
			Spool:   spool,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node),
			Alias:   make(map[string]*NodeId),
			LogPath: filepath.Join(spool, "log.log"),
			Debug:   TDebug,
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		files := make(map[string][]byte)
		for i, fileSize := range fileSizes {
			fileData := make([]byte, fileSize)
			if _, err := io.ReadFull(rand.Reader, fileData); err != nil {
				panic(err)
			}
			fileName := strconv.Itoa(i)
			files[fileName] = fileData
			if err := ctx.TxFreq(
				ctx.Neigh[*nodeOur.Id],
				DefaultNiceFreq,
				replyNice,
				fileName,
				fileName,
				1<<15,
			); err != nil {
				t.Error(err)
				return false
			}
		}
		rxPath := filepath.Join(spool, ctx.Self.Id.String(), string(TRx))
		txPath := filepath.Join(spool, ctx.Self.Id.String(), string(TTx))
		os.Rename(txPath, rxPath)
		os.MkdirAll(txPath, os.FileMode(0700))
		ctx.Toss(ctx.Self.Id, DefaultNiceFreq, false, false, false, false, false, false)
		if len(dirFiles(txPath)) != 0 || len(dirFiles(rxPath)) == 0 {
			return false
		}
		ctx.Neigh[*nodeOur.Id].Freq = &spool
		ctx.Toss(ctx.Self.Id, DefaultNiceFreq, false, false, false, false, false, false)
		if len(dirFiles(txPath)) != 0 || len(dirFiles(rxPath)) == 0 {
			return false
		}
		for fileName, fileData := range files {
			if err := ioutil.WriteFile(
				filepath.Join(spool, fileName),
				fileData,
				os.FileMode(0600),
			); err != nil {
				panic(err)
			}
		}
		ctx.Toss(ctx.Self.Id, DefaultNiceFreq, false, false, false, false, false, false)
		if len(dirFiles(txPath)) == 0 || len(dirFiles(rxPath)) != 0 {
			return false
		}
		for job := range ctx.Jobs(ctx.Self.Id, TTx) {
			var buf bytes.Buffer
			_, _, err := PktEncRead(ctx.Self, ctx.Neigh, job.Fd, &buf)
			if err != nil {
				t.Error(err)
				return false
			}
			var pkt Pkt
			if _, err = xdr.Unmarshal(&buf, &pkt); err != nil {
				t.Error(err)
				return false
			}
			if pkt.Nice != replyNice {
				return false
			}
			dst := string(pkt.Path[:int(pkt.PathLen)])
			if bytes.Compare(buf.Bytes(), files[dst]) != 0 {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTossTrns(t *testing.T) {
	f := func(datumLens []uint8) bool {
		if len(datumLens) == 0 {
			return true
		}
		datum := make(map[int][]byte)
		for i, datumLen := range datumLens {
			datumLen += 64
			data := make([]byte, datumLen)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				panic(err)
			}
			datum[i] = data
		}
		spool, err := ioutil.TempDir("", "testtoss")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(spool)
		nodeOur, err := NewNodeGenerate()
		if err != nil {
			t.Error(err)
			return false
		}
		ctx := Ctx{
			Spool:   spool,
			Self:    nodeOur,
			SelfId:  nodeOur.Id,
			Neigh:   make(map[NodeId]*Node),
			Alias:   make(map[string]*NodeId),
			LogPath: filepath.Join(spool, "log.log"),
			Debug:   TDebug,
		}
		ctx.Neigh[*nodeOur.Id] = nodeOur.Their()
		rxPath := filepath.Join(spool, ctx.Self.Id.String(), string(TRx))
		os.MkdirAll(rxPath, os.FileMode(0700))
		txPath := filepath.Join(spool, ctx.Self.Id.String(), string(TTx))
		os.MkdirAll(txPath, os.FileMode(0700))
		for _, data := range datum {
			pktTrans := Pkt{
				Magic:   MagicNNCPPv2,
				Type:    PktTypeTrns,
				PathLen: blake2b.Size256,
				Path:    new([MaxPathSize]byte),
			}
			copy(pktTrans.Path[:], nodeOur.Id[:])
			var dst bytes.Buffer
			if err := PktEncWrite(
				ctx.Self,
				ctx.Neigh[*nodeOur.Id],
				&pktTrans,
				123,
				int64(len(data)),
				0,
				bytes.NewReader(data),
				&dst,
			); err != nil {
				t.Error(err)
				return false
			}
			checksum := blake2b.Sum256(dst.Bytes())
			if err := ioutil.WriteFile(
				filepath.Join(rxPath, ToBase32(checksum[:])),
				dst.Bytes(),
				os.FileMode(0600),
			); err != nil {
				panic(err)
			}
		}
		ctx.Toss(ctx.Self.Id, 123, false, false, false, false, false, false)
		if len(dirFiles(rxPath)) != 0 {
			return false
		}
		for _, filename := range dirFiles(txPath) {
			dataRead, err := ioutil.ReadFile(filepath.Join(txPath, filename))
			if err != nil {
				panic(err)
			}
			for k, data := range datum {
				if bytes.Compare(dataRead, data) == 0 {
					delete(datum, k)
				}
			}
		}
		if len(datum) > 0 {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
