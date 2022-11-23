//go:build !nofsnotify
// +build !nofsnotify

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
	"time"

	"github.com/fsnotify/fsnotify"
)

type DirWatcher struct {
	w      *fsnotify.Watcher
	C      chan struct{}
	isDead chan struct{}
}

func (ctx *Ctx) NewDirWatcher(dir string, d time.Duration) (*DirWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = ensureDir(dir)
	if err != nil {
		return nil, err
	}
	err = w.Add(dir)
	if err != nil {
		w.Close()
		return nil, err
	}
	dw := DirWatcher{
		w:      w,
		C:      make(chan struct{}),
		isDead: make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(d)
		dw.C <- struct{}{}
		hasEvents := false
		for {
			select {
			case err := <-w.Errors:
				ctx.LogE("dir-watch", LEs{{"Dir", dir}}, err, func(les LEs) string {
					return "fsnotify error: " + err.Error()
				})
			case e := <-w.Events:
				ctx.LogD("dir-watch-event", LEs{{"Dir", dir}}, func(les LEs) string {
					return fmt.Sprintf("fsnotify event: %v", e)
				})
				if e.Op&(fsnotify.Create|fsnotify.Rename) > 0 {
					hasEvents = true
				}
			case <-ticker.C:
				if hasEvents {
					dw.C <- struct{}{}
					hasEvents = false
				}
			case <-dw.isDead:
				w.Close()
				ticker.Stop()
				close(dw.C)
				return
			}
		}
	}()
	return &dw, err
}

func (dw *DirWatcher) Close() {
	close(dw.isDead)
	for range dw.C {
	}
}
