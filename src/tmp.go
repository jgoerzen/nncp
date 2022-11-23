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
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var NoSync bool

func init() {
	NoSync = os.Getenv(CfgNoSync) != ""
}

func TempFile(dir, prefix string) (*os.File, error) {
	// Assume that probability of suffix collision is negligible
	suffix := strconv.FormatInt(time.Now().UnixNano()+int64(os.Getpid()), 16)
	name := filepath.Join(dir, "nncp"+prefix+suffix)
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
}

func (ctx *Ctx) NewTmpFile() (*os.File, error) {
	jobsPath := filepath.Join(ctx.Spool, "tmp")
	if err := ensureDir(jobsPath); err != nil {
		return nil, err
	}
	fd, err := TempFile(jobsPath, "")
	if err == nil {
		ctx.LogD("tmp", LEs{{"Src", fd.Name()}}, func(les LEs) string {
			return "Temporary file created: " + fd.Name()
		})
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
	hsh := MTHNew(0, 0)
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

func DirSync(dirPath string) error {
	if NoSync {
		return nil
	}
	fd, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	err = fd.Sync()
	if err != nil {
		fd.Close()
		return err
	}
	return fd.Close()
}

func (tmp *TmpFileWHash) Checksum() string {
	return Base32Codec.EncodeToString(tmp.Hsh.Sum(nil))
}

func (tmp *TmpFileWHash) Commit(dir string) error {
	var err error
	if err = ensureDir(dir); err != nil {
		return err
	}
	if err = tmp.W.Flush(); err != nil {
		tmp.Fd.Close()
		return err
	}
	if !NoSync {
		if err = tmp.Fd.Sync(); err != nil {
			tmp.Fd.Close()
			return err
		}
	}
	if err = tmp.Fd.Close(); err != nil {
		return err
	}
	checksum := tmp.Checksum()
	tmp.ctx.LogD(
		"tmp-rename",
		LEs{{"Src", tmp.Fd.Name()}, {"Dst", checksum}},
		func(les LEs) string {
			return fmt.Sprintf("Temporary file: %s -> %s", tmp.Fd.Name(), checksum)
		},
	)
	if err = os.Rename(tmp.Fd.Name(), filepath.Join(dir, checksum)); err != nil {
		return err
	}
	return DirSync(dir)
}
