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
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type Ctx struct {
	Self   *NodeOur
	SelfId *NodeId
	Neigh  map[NodeId]*Node
	Alias  map[string]*NodeId

	Spool      string
	LogPath    string
	Quiet      bool
	Debug      bool
	NotifyFile *FromToYAML
	NotifyFreq *FromToYAML
}

func (ctx *Ctx) FindNode(id string) (*Node, error) {
	nodeId, known := ctx.Alias[id]
	if known {
		return ctx.Neigh[*nodeId], nil
	}
	nodeId, err := NodeIdFromString(id)
	if err != nil {
		return nil, err
	}
	node, known := ctx.Neigh[*nodeId]
	if !known {
		return nil, errors.New("Unknown node")
	}
	return node, nil
}

func (ctx *Ctx) ensureRxDir(nodeId *NodeId) error {
	dirPath := filepath.Join(ctx.Spool, nodeId.String(), string(TRx))
	if err := os.MkdirAll(dirPath, os.FileMode(0700)); err != nil {
		ctx.LogE("dir-ensure", SDS{"dir": dirPath, "err": err}, "")
		return err
	}
	fd, err := os.Open(dirPath)
	if err != nil {
		ctx.LogE("dir-ensure", SDS{"dir": dirPath, "err": err}, "")
		return err
	}
	fd.Close()
	return nil
}

func CtxFromCmdline(cfgPath, spoolPath, logPath string, quiet, debug bool) (*Ctx, error) {
	env := os.Getenv(CfgPathEnv)
	if env != "" {
		cfgPath = env
	}
	cfgRaw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	ctx, err := CfgParse(cfgRaw)
	if err != nil {
		return nil, err
	}
	if spoolPath == "" {
		env = os.Getenv(CfgSpoolEnv)
		if env != "" {
			ctx.Spool = env
		}
	} else {
		ctx.Spool = spoolPath
	}
	if logPath == "" {
		env = os.Getenv(CfgLogEnv)
		if env != "" {
			ctx.LogPath = env
		}
	} else {
		ctx.LogPath = logPath
	}
	ctx.Quiet = quiet
	ctx.Debug = debug
	return ctx, nil
}

func (ctx *Ctx) IsEnoughSpace(want int64) bool {
	var s unix.Statfs_t
	if err := unix.Statfs(ctx.Spool, &s); err != nil {
		log.Fatalln(err)
	}
	return int64(s.Bavail)*int64(s.Bsize) > want
}
