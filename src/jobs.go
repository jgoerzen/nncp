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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
)

type TRxTx string

const (
	TRx TRxTx = "rx"
	TTx TRxTx = "tx"

	HdrDir = "hdr"
)

type Job struct {
	PktEnc   *PktEnc
	Path     string
	Size     int64
	HshValue *[MTHSize]byte
}

func JobPath2Hdr(jobPath string) string {
	return filepath.Join(filepath.Dir(jobPath), HdrDir, filepath.Base(jobPath))
}

func (ctx *Ctx) HdrRead(r io.Reader) (*PktEnc, []byte, error) {
	var pktEnc PktEnc
	_, err := xdr.Unmarshal(r, &pktEnc)
	if err != nil {
		return nil, nil, err
	}
	var raw bytes.Buffer
	if _, err = xdr.Marshal(&raw, pktEnc); err != nil {
		panic(err)
	}
	return &pktEnc, raw.Bytes(), nil
}

func (ctx *Ctx) HdrWrite(pktEncRaw []byte, tgt string) error {
	tmpHdr, err := ctx.NewTmpFile()
	if err != nil {
		ctx.LogE("hdr-write-tmp-new", nil, err, func(les LEs) string {
			return "Header writing: new temporary file"
		})
		return err
	}
	if _, err = tmpHdr.Write(pktEncRaw); err != nil {
		ctx.LogE("hdr-write-write", nil, err, func(les LEs) string {
			return "Header writing: writing"
		})
		os.Remove(tmpHdr.Name())
		return err
	}
	if err = tmpHdr.Close(); err != nil {
		ctx.LogE("hdr-write-close", nil, err, func(les LEs) string {
			return "Header writing: closing"
		})
		os.Remove(tmpHdr.Name())
		return err
	}
	if err = ensureDir(filepath.Dir(tgt), HdrDir); err != nil {
		ctx.LogE("hdr-write-ensure-mkdir", nil, err, func(les LEs) string {
			return "Header writing: ensuring directory"
		})
		return err
	}
	if err = os.Rename(tmpHdr.Name(), JobPath2Hdr(tgt)); err != nil {
		ctx.LogE("hdr-write-rename", nil, err, func(les LEs) string {
			return "Header writing: renaming"
		})
		return err
	}
	return err
}

func (ctx *Ctx) jobsFind(nodeId *NodeId, xx TRxTx, nock, part bool) chan Job {
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
			name := fi.Name()
			var hshValue []byte
			if nock {
				if !strings.HasSuffix(name, NoCKSuffix) ||
					len(name) != Base32Encoded32Len+len(NoCKSuffix) {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(
					strings.TrimSuffix(name, NoCKSuffix),
				)
			} else if part {
				if !strings.HasSuffix(name, PartSuffix) ||
					len(name) != Base32Encoded32Len+len(PartSuffix) {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(
					strings.TrimSuffix(name, PartSuffix),
				)
			} else {
				if len(name) != Base32Encoded32Len {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(name)
			}
			if err != nil {
				continue
			}
			pth := filepath.Join(rxPath, name)
			hdrExists := true
			var fd *os.File
			if nock || part {
				fd, err = os.Open(pth)
			} else {
				fd, err = os.Open(JobPath2Hdr(pth))
				if err != nil && os.IsNotExist(err) {
					hdrExists = false
					fd, err = os.Open(pth)
				}
			}
			if err != nil {
				continue
			}
			if part {
				job := Job{
					Path:     pth,
					Size:     fi.Size(),
					HshValue: new([MTHSize]byte),
				}
				copy(job.HshValue[:], hshValue)
				jobs <- job
				continue
			}
			pktEnc, pktEncRaw, err := ctx.HdrRead(fd)
			fd.Close()
			if err != nil {
				continue
			}
			switch pktEnc.Magic {
			case MagicNNCPEv1.B:
				err = MagicNNCPEv1.TooOld()
			case MagicNNCPEv2.B:
				err = MagicNNCPEv2.TooOld()
			case MagicNNCPEv3.B:
				err = MagicNNCPEv3.TooOld()
			case MagicNNCPEv4.B:
				err = MagicNNCPEv4.TooOld()
			case MagicNNCPEv5.B:
				err = MagicNNCPEv5.TooOld()
			case MagicNNCPEv6.B:
			default:
				err = BadMagic
			}
			if err != nil {
				ctx.LogE("job", LEs{
					{"XX", string(xx)},
					{"Name", name},
					{"Size", fi.Size()},
				}, err, func(les LEs) string {
					return fmt.Sprintf(
						"Job %s/%s size: %s",
						string(xx), name,
						humanize.IBytes(uint64(fi.Size())),
					)
				})
				continue
			}
			ctx.LogD("job", LEs{
				{"XX", string(xx)},
				{"Node", pktEnc.Sender},
				{"Name", name},
				{"Nice", int(pktEnc.Nice)},
				{"Size", fi.Size()},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Job %s/%s/%s nice: %s size: %s",
					pktEnc.Sender, string(xx), name,
					NicenessFmt(pktEnc.Nice),
					humanize.IBytes(uint64(fi.Size())),
				)
			})
			if !hdrExists && ctx.HdrUsage {
				ctx.HdrWrite(pktEncRaw, pth)
			}
			job := Job{
				PktEnc:   pktEnc,
				Path:     pth,
				Size:     fi.Size(),
				HshValue: new([MTHSize]byte),
			}
			copy(job.HshValue[:], hshValue)
			jobs <- job
		}
	}()
	return jobs
}

func (ctx *Ctx) Jobs(nodeId *NodeId, xx TRxTx) chan Job {
	return ctx.jobsFind(nodeId, xx, false, false)
}

func (ctx *Ctx) JobsNoCK(nodeId *NodeId) chan Job {
	return ctx.jobsFind(nodeId, TRx, true, false)
}

func (ctx *Ctx) JobsPart(nodeId *NodeId) chan Job {
	return ctx.jobsFind(nodeId, TRx, false, true)
}
