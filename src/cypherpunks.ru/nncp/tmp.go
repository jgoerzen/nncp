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
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
)

func (ctx *Ctx) NewTmpFile() (*os.File, error) {
	jobsPath := filepath.Join(ctx.Spool, "tmp")
	var err error
	if err = os.MkdirAll(jobsPath, os.FileMode(0700)); err != nil {
		return nil, err
	}
	fd, err := ioutil.TempFile(jobsPath, "")
	if err == nil {
		ctx.LogD("tmp", SDS{"src": fd.Name()}, "created")
	}
	return fd, err
}

type TmpFileWHash struct {
	W   *bufio.Writer
	Fd  *os.File
	Hsh hash.Hash
	ctx *Ctx
}

func (ctx *Ctx) NewTmpFileWHash() (*TmpFileWHash, error) {
	tmp, err := ctx.NewTmpFile()
	if err != nil {
		return nil, err
	}
	hsh, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	return &TmpFileWHash{
		W:   bufio.NewWriter(io.MultiWriter(hsh, tmp)),
		Fd:  tmp,
		Hsh: hsh,
		ctx: ctx,
	}, nil
}

func (tmp *TmpFileWHash) Cancel() {
	tmp.Fd.Truncate(0)
	tmp.Fd.Close()
	os.Remove(tmp.Fd.Name())
}

func (tmp *TmpFileWHash) Commit(dir string) error {
	var err error
	if err = os.MkdirAll(dir, os.FileMode(0700)); err != nil {
		return err
	}
	if err = tmp.W.Flush(); err != nil {
		tmp.Fd.Close()
		return err
	}
	if err = tmp.Fd.Sync(); err != nil {
		tmp.Fd.Close()
		return err
	}
	tmp.Fd.Close()
	checksum := ToBase32(tmp.Hsh.Sum(nil))
	tmp.ctx.LogD("tmp", SDS{"src": tmp.Fd.Name(), "dst": checksum}, "commit")
	return os.Rename(tmp.Fd.Name(), filepath.Join(dir, checksum))
}
