//go:build nofsnotify
// +build nofsnotify

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
	"time"
)

type DirWatcher struct {
	C      chan struct{}
	ticker *time.Ticker
}

func (ctx *Ctx) NewDirWatcher(dir string, d time.Duration) (*DirWatcher, error) {
	dw := DirWatcher{C: make(chan struct{}), ticker: time.NewTicker(d)}
	go func() {
		for range dw.ticker.C {
			dw.C <- struct{}{}
		}
	}()
	return &dw, nil
}

func (dw *DirWatcher) Close() {
	dw.ticker.Stop()
	for range dw.C {
	}
}
