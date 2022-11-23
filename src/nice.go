package nncp

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	NiceFlash    = 32
	NicePriority = 96
	NiceNormal   = 160
	NiceBulk     = 224

	DefaultNiceExec = NicePriority
	DefaultNiceFreq = NiceNormal
	DefaultNiceFile = NiceBulk
)

var (
	niceRe      *regexp.Regexp   = regexp.MustCompile(`^(\w+)([-+])(\d+)$`)
	niceAliases map[string]uint8 = map[string]uint8{
		"flash":    NiceFlash,
		"f":        NiceFlash,
		"priority": NicePriority,
		"p":        NicePriority,
		"normal":   NiceNormal,
		"n":        NiceNormal,
		"bulk":     NiceBulk,
		"b":        NiceBulk,
		"max":      255,
	}
)

func NicenessParse(s string) (uint8, error) {
	if nice, err := strconv.Atoi(s); err == nil {
		if nice <= 0 || nice > 255 {
			return 0, errors.New("nice out of bounds")
		}
		return uint8(nice), nil
	}
	s = strings.ToLower(s)
	var baseNice uint8
	var found bool
	if baseNice, found = niceAliases[s]; found {
		return baseNice, nil
	}
	matches := niceRe.FindStringSubmatch(s)
	if len(matches) != 1+3 {
		return 0, errors.New("invalid niceness")
	}
	baseNice, found = niceAliases[matches[1]]
	if !found {
		return 0, errors.New("invalid niceness")
	}
	delta, err := strconv.Atoi(matches[3])
	if err != nil {
		return 0, err
	}
	if matches[2] == "-" {
		if delta > 31 {
			return 0, errors.New("too big niceness delta")
		}
		return baseNice - uint8(delta), nil
	}
	if delta > 32 || (baseNice == NiceBulk && delta > 31) {
		return 0, errors.New("too big niceness delta")
	}
	return baseNice + uint8(delta), nil
}

func NicenessFmt(nice uint8) string {
	switch {
	case nice == 255:
		return "MAX"
	case NiceFlash-31 < nice && nice < NiceFlash:
		return fmt.Sprintf("F-%d", NiceFlash-nice)
	case nice == NiceFlash:
		return "F"
	case NiceFlash < nice && nice <= (NiceFlash+32):
		return fmt.Sprintf("F+%d", nice-NiceFlash)

	case NicePriority-31 < nice && nice < NicePriority:
		return fmt.Sprintf("P-%d", NicePriority-nice)
	case nice == NicePriority:
		return "P"
	case NicePriority < nice && nice <= (NicePriority+32):
		return fmt.Sprintf("P+%d", nice-NicePriority)

	case NiceNormal-31 < nice && nice < NiceNormal:
		return fmt.Sprintf("N-%d", NiceNormal-nice)
	case nice == NiceNormal:
		return "N"
	case NiceNormal < nice && nice <= (NiceNormal+32):
		return fmt.Sprintf("N+%d", nice-NiceNormal)

	case NiceBulk-31 < nice && nice < NiceBulk:
		return fmt.Sprintf("B-%d", NiceBulk-nice)
	case nice == NiceBulk:
		return "B"
	case NiceBulk < nice && nice <= (NiceBulk+30):
		return fmt.Sprintf("B+%d", nice-NiceBulk)
	}
	return strconv.Itoa(int(nice))
}

type ByNice []*SPInfo

func (a ByNice) Len() int {
	return len(a)
}

func (a ByNice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByNice) Less(i, j int) bool {
	return a[i].Nice < a[j].Nice
}
