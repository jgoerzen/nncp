/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2020 Sergey Matveev <stargrave@stargrave.org>

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
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"
)

func TempFile(dir, prefix string) (*os.File, error) {
	// Assume that probability of suffix collision is negligible
	suffix := strconv.FormatInt(time.Now().UnixNano()+int64(os.Getpid()), 16)
	name := filepath.Join(dir, "nncp"+prefix+suffix)
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
}

func (ctx *Ctx) NewTmpFile() (*os.File, error) {
	jobsPath := filepath.Join(ctx.Spool, "tmp")
	var err error
	if err = os.MkdirAll(jobsPath, os.FileMode(0777)); err != nil {
		return nil, err
	}
	fd, err := TempFile(jobsPath, "")
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
	tmp.Fd.Truncate(0) // #nosec G104
	tmp.Fd.Close() // #nosec G104
	os.Remove(tmp.Fd.Name()) // #nosec G104
}

func DirSync(dirPath string) error {
	fd, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	err = fd.Sync()
	if err != nil {
		fd.Close() // #nosec G104
		return err
	}
	return fd.Close()
}

func (tmp *TmpFileWHash) Commit(dir string) error {
	var err error
	if err = os.MkdirAll(dir, os.FileMode(0777)); err != nil {
		return err
	}
	if err = tmp.W.Flush(); err != nil {
		tmp.Fd.Close() // #nosec G104
		return err
	}
	if err = tmp.Fd.Sync(); err != nil {
		tmp.Fd.Close() // #nosec G104
		return err
	}
	if err = tmp.Fd.Close(); err != nil {
		return err
	}
	checksum := Base32Codec.EncodeToString(tmp.Hsh.Sum(nil))
	tmp.ctx.LogD("tmp", SDS{"src": tmp.Fd.Name(), "dst": checksum}, "commit")
	if err = os.Rename(tmp.Fd.Name(), filepath.Join(dir, checksum)); err != nil {
		return err
	}
	return DirSync(dir)
}
