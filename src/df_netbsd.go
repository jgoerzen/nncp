//go:build netbsd
// +build netbsd

package nncp

import (
	"log"

	"golang.org/x/sys/unix"
)

func (ctx *Ctx) IsEnoughSpace(want int64) bool {
	var s unix.Statvfs_t
	if err := unix.Statvfs(ctx.Spool, &s); err != nil {
		log.Fatalln("Can not stat spool:", err)
	}
	return int64(s.Bavail)*int64(s.Frsize) > want
}
