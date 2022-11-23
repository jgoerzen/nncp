//go:build !netbsd && !openbsd
// +build !netbsd,!openbsd

package nncp

import (
	"log"

	"golang.org/x/sys/unix"
)

func (ctx *Ctx) IsEnoughSpace(want int64) bool {
	var s unix.Statfs_t
	if err := unix.Statfs(ctx.Spool, &s); err != nil {
		log.Fatalln("Can not stat spool:", err)
	}
	return int64(s.Bavail)*int64(s.Bsize) > want
}
