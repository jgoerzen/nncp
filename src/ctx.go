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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"syscall"
)

type Ctx struct {
	Self   *NodeOur
	SelfId *NodeId
	Neigh  map[NodeId]*Node
	Alias  map[string]*NodeId

	AreaId2Area map[AreaId]*Area
	AreaName2Id map[string]*AreaId

	Spool      string
	LogPath    string
	UmaskForce *int
	Quiet      bool
	ShowPrgrs  bool
	HdrUsage   bool
	Debug      bool
	NotifyFile *FromToJSON
	NotifyFreq *FromToJSON
	NotifyExec map[string]*FromToJSON

	MCDRxIfis []string
	MCDTxIfis map[string]int

	YggdrasilAliases map[string]string
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

func ensureDir(dirs ...string) error {
	p := filepath.Join(dirs...)
	fi, err := os.Stat(p)
	if err == nil {
		if fi.IsDir() {
			return nil
		}
		return fmt.Errorf("%s: is not a directory", p)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(p, os.FileMode(0777))
}

func (ctx *Ctx) ensureRxDir(nodeId *NodeId) error {
	dirPath := filepath.Join(ctx.Spool, nodeId.String(), string(TRx))
	err := ensureDir(dirPath)
	if err != nil {
		ctx.LogE("dir-ensure-mkdir", LEs{{"Dir", dirPath}}, err, func(les LEs) string {
			return fmt.Sprintf("Ensuring directory %s existence", dirPath)
		})
	}
	return err
}

func CtxFromCmdline(
	cfgPath, spoolPath, logPath string,
	quiet, showPrgrs, omitPrgrs, debug bool,
) (*Ctx, error) {
	env := os.Getenv(CfgPathEnv)
	if env != "" {
		cfgPath = env
	}
	if showPrgrs && omitPrgrs {
		return nil, errors.New("simultaneous -progress and -noprogress")
	}
	fi, err := os.Stat(cfgPath)
	if err != nil {
		return nil, err
	}
	var cfg *CfgJSON
	if fi.IsDir() {
		cfg, err = DirToCfg(cfgPath)
		if err != nil {
			return nil, err
		}
	} else {
		cfgRaw, err := ioutil.ReadFile(cfgPath)
		if err != nil {
			return nil, err
		}
		cfg, err = CfgParse(cfgRaw)
		if err != nil {
			return nil, err
		}
	}
	ctx, err := Cfg2Ctx(cfg)
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
	if strings.HasPrefix(ctx.LogPath, LogFdPrefix) {
		ptr, err := strconv.ParseUint(
			strings.TrimPrefix(ctx.LogPath, LogFdPrefix), 10, 64,
		)
		if err != nil {
			return nil, err
		}
		LogFd = os.NewFile(uintptr(ptr), CfgLogEnv)
		if LogFd == nil {
			return nil, errors.New("can not open:" + ctx.LogPath)
		}
	}
	if showPrgrs {
		ctx.ShowPrgrs = true
	}
	if quiet || omitPrgrs {
		ctx.ShowPrgrs = false
	}
	ctx.Quiet = quiet
	ctx.Debug = debug
	return ctx, nil
}

func (ctx *Ctx) Umask() {
	if ctx.UmaskForce != nil {
		syscall.Umask(*ctx.UmaskForce)
	}
}
