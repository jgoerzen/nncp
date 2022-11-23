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
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v8/uilive"
)

func init() {
	uilive.Out = os.Stderr
}

var progressBars = make(map[string]*ProgressBar)
var progressBarsLock sync.RWMutex

type ProgressBar struct {
	w       *uilive.Writer
	hash    string
	started time.Time
	initial int64
	full    int64
}

func ProgressBarNew(initial, full int64) *ProgressBar {
	pb := ProgressBar{
		w:       uilive.New(),
		started: time.Now(),
		initial: initial,
		full:    full,
	}
	pb.w.Start()
	return &pb
}

func (pb ProgressBar) Render(what string, size int64) {
	now := time.Now().UTC()
	timeDiff := now.Sub(pb.started).Seconds()
	if timeDiff == 0 {
		timeDiff = 1
	}
	percentage := int64(100)
	if pb.full > 0 {
		percentage = 100 * size / pb.full
	}
	fmt.Fprintf(
		pb.w, "%s %s %s/%s %d%% (%s/sec)\n",
		now.Format(time.RFC3339), what,
		humanize.IBytes(uint64(size)),
		humanize.IBytes(uint64(pb.full)),
		percentage,
		humanize.IBytes(uint64(float64(size-pb.initial)/timeDiff)),
	)
}

func (pb ProgressBar) Kill() {
	pb.w.Stop()
}

func CopyProgressed(
	dst io.Writer,
	src io.Reader,
	prgrsPrefix string,
	les LEs,
	showPrgrs bool,
) (written int64, err error) {
	buf := make([]byte, EncBlkSize)
	var nr, nw int
	var er, ew error
	for {
		nr, er = src.Read(buf)
		if nr > 0 {
			nw, ew = dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if showPrgrs {
					Progress(prgrsPrefix, append(les, LE{"Size", written}))
				}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	if showPrgrs {
		for _, le := range les {
			if le.K == "FullSize" {
				if le.V.(int64) == 0 {
					Progress(prgrsPrefix, append(
						les, LE{"Size", written}, LE{"FullSize", written},
					))
				}
				break
			}
		}
	}
	return
}

func Progress(prefix string, les LEs) {
	var size int64
	var fullsize int64
	var pkt string
	for _, le := range les {
		switch le.K {
		case "Size":
			size = le.V.(int64)
		case "FullSize":
			fullsize = le.V.(int64)
		case "Pkt":
			pkt = le.V.(string)
		}
	}
	progressBarsLock.RLock()
	pb := progressBars[pkt]
	progressBarsLock.RUnlock()
	if pb == nil {
		progressBarsLock.Lock()
		pb = ProgressBarNew(size, fullsize)
		progressBars[pkt] = pb
		progressBarsLock.Unlock()
	}
	what := pkt
	if len(what) >= Base32Encoded32Len { // Base32 encoded
		what = what[:16] + ".." + what[len(what)-16:]
	}
	what = prefix + " " + what
	pb.Render(what, size)
	if fullsize != 0 && size >= fullsize {
		pb.Kill()
		progressBarsLock.Lock()
		delete(progressBars, pkt)
		progressBarsLock.Unlock()
	}
}

func ProgressKill(pkt string) {
	progressBarsLock.Lock()
	pb := progressBars[pkt]
	if pb != nil {
		pb.Kill()
		delete(progressBars, pkt)
	}
	progressBarsLock.Unlock()
}
