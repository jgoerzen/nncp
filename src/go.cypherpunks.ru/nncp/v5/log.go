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
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type LogLevel string

type SDS map[string]interface{}

func sdFmt(who string, sds SDS) string {
	keys := make([]string, 0, len(sds))
	for k, _ := range sds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]string, 0, 1+len(keys))
	result = append(result, "["+who)
	for _, k := range keys {
		var value string
		switch v := sds[k].(type) {
		case int, int8, uint8, int64, uint64:
			value = fmt.Sprintf("%d", v)
		default:
			value = fmt.Sprintf("%s", v)
		}
		result = append(result, fmt.Sprintf(`%s="%s"`, k, value))
	}
	return strings.Join(result, " ") + "]"
}

func msgFmt(level LogLevel, who string, sds SDS, msg string) string {
	result := fmt.Sprintf(
		"%s %s %s",
		level,
		time.Now().UTC().Format(time.RFC3339Nano),
		sdFmt(who, sds),
	)
	if len(msg) > 0 {
		result += " " + msg
	}
	return result + "\n"
}

func (ctx *Ctx) Log(msg string) {
	fdLock, err := os.OpenFile(
		ctx.LogPath+".lock",
		os.O_CREATE|os.O_WRONLY,
		os.FileMode(0666),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not open lock for log:", err)
		return
	}
	fdLockFd := int(fdLock.Fd())
	err = unix.Flock(fdLockFd, unix.LOCK_EX)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not acquire lock for log:", err)
		return
	}
	defer unix.Flock(fdLockFd, unix.LOCK_UN)
	fd, err := os.OpenFile(
		ctx.LogPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		os.FileMode(0666),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not open log:", err)
		return
	}
	fd.WriteString(msg) // #nosec G104
	fd.Close()          // #nosec G104
}

func (ctx *Ctx) LogD(who string, sds SDS, msg string) {
	if !ctx.Debug {
		return
	}
	fmt.Fprint(os.Stderr, msgFmt(LogLevel("D"), who, sds, msg))
}

func (ctx *Ctx) LogI(who string, sds SDS, msg string) {
	msg = msgFmt(LogLevel("I"), who, sds, msg)
	if !ctx.Quiet {
		fmt.Fprintln(os.Stderr, ctx.Humanize(msg))
	}
	ctx.Log(msg)
}

func (ctx *Ctx) LogE(who string, sds SDS, err error, msg string) {
	sds["err"] = err.Error()
	msg = msgFmt(LogLevel("E"), who, sds, msg)
	if len(msg) > 2048 {
		msg = msg[:2048]
	}
	fmt.Fprintln(os.Stderr, ctx.Humanize(msg))
	ctx.Log(msg)
}

func SdsAdd(sds, add SDS) SDS {
	neu := SDS{}
	for k, v := range sds {
		neu[k] = v
	}
	for k, v := range add {
		neu[k] = v
	}
	return neu
}
