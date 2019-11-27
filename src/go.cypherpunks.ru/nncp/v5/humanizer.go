/*
NNCP -- Node to Node copy
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

func (ctx *Ctx) Humanize(s string) string {
	s = strings.TrimRight(s, "\n")
	splitted := strings.SplitN(s, " ", 4)
	if len(splitted) != 4 {
		return s
	}
	var level string
	if splitted[0] == "E" {
		level = "ERROR "
	}
	when, err := time.Parse(time.RFC3339Nano, splitted[1])
	if err != nil {
		return s
	}
	who := splitted[2][1:]
	closingBracket := strings.LastIndex(splitted[3], "]")
	if closingBracket == -1 {
		return s
	}
	rem := strings.Trim(splitted[3][closingBracket+1:], " ")
	sds := make(map[string]string)

	re := regexp.MustCompile(`\w+="[^"]+"`)
	for _, pair := range re.FindAllString(splitted[3][:closingBracket+1], -1) {
		sep := strings.Index(pair, "=")
		sds[pair[:sep]] = pair[sep+2 : len(pair)-1]
	}

	nodeS := sds["node"]
	node, err := ctx.FindNode(nodeS)
	if err == nil {
		nodeS = node.Name
	}
	var size string
	if sizeRaw, exists := sds["size"]; exists {
		sp, err := strconv.ParseUint(sizeRaw, 10, 64)
		if err != nil {
			return s
		}
		size = humanize.IBytes(uint64(sp))
	}

	var msg string
	switch who {
	case "tx":
		switch sds["type"] {
		case "file":
			msg = fmt.Sprintf(
				"File %s (%s) transfer to %s:%s: %s",
				sds["src"], size, nodeS, sds["dst"], rem,
			)
		case "freq":
			msg = fmt.Sprintf(
				"File request from %s:%s to %s: %s",
				nodeS, sds["src"], sds["dst"], rem,
			)
		case "exec":
			msg = fmt.Sprintf(
				"Exec to %s@%s (%s): %s",
				nodeS, sds["dst"], size, rem,
			)
		case "trns":
			msg = fmt.Sprintf(
				"Transitional packet to %s (%s) (nice %s): %s",
				nodeS, size, sds["nice"], rem,
			)
		default:
			return s
		}
		if err, exists := sds["err"]; exists {
			msg += ": " + err
		}
	case "rx":
		switch sds["type"] {
		case "exec":
			msg = fmt.Sprintf(
				"Got exec from %s to %s (%s)",
				nodeS, sds["dst"], size,
			)
		case "file":
			msg = fmt.Sprintf("Got file %s (%s) from %s", sds["dst"], size, nodeS)
		case "freq":
			msg = fmt.Sprintf("Got file request %s to %s", sds["src"], nodeS)
		case "trns":
			nodeT := sds["dst"]
			node, err := ctx.FindNode(nodeT)
			if err == nil {
				nodeT = node.Name
			}
			msg = fmt.Sprintf(
				"Got transitional packet from %s to %s (%s)",
				nodeS, nodeT, size,
			)
		default:
			return s
		}
		if err, exists := sds["err"]; exists {
			msg += ": " + err
		}
	case "check":
		msg = fmt.Sprintf("Checking: %s/%s/%s", sds["node"], sds["xx"], sds["pkt"])
		if err, exists := sds["err"]; exists {
			msg += fmt.Sprintf(" %s", err)
		}
	case "nncp-xfer":
		switch sds["xx"] {
		case "rx":
			msg = "Packet transfer, received from"
		case "tx":
			msg = "Packet transfer, sent to"
		default:
			return s
		}
		if nodeS != "" {
			msg += " node " + nodeS
		}
		if size != "" {
			msg += fmt.Sprintf(" (%s)", size)
		}
		if err, exists := sds["err"]; exists {
			msg += ": " + err
		} else {
			msg += " " + rem
		}
	case "nncp-bundle":
		switch sds["xx"] {
		case "rx":
			msg = "Bundle transfer, received from"
		case "tx":
			msg = "Bundle transfer, sent to"
		default:
			return s
		}
		if nodeS != "" {
			msg += " node " + nodeS
		}
		msg += " " + sds["pkt"]
		if size != "" {
			msg += fmt.Sprintf(" (%s)", size)
		}
		if err, exists := sds["err"]; exists {
			msg += ": " + err
		}
	case "nncp-rm":
		msg += "removing " + sds["file"]
	case "call-start":
		msg = fmt.Sprintf("Connected to %s", nodeS)
	case "call-finish":
		rx, err := strconv.ParseUint(sds["rxbytes"], 10, 64)
		if err != nil {
			return s
		}
		rxs, err := strconv.ParseUint(sds["rxspeed"], 10, 64)
		if err != nil {
			return s
		}
		tx, err := strconv.ParseUint(sds["txbytes"], 10, 64)
		if err != nil {
			return s
		}
		txs, err := strconv.ParseUint(sds["txspeed"], 10, 64)
		if err != nil {
			return s
		}
		msg = fmt.Sprintf(
			"Finished call with %s: %s received (%s/sec), %s transferred (%s/sec)",
			nodeS,
			humanize.IBytes(uint64(rx)), humanize.IBytes(uint64(rxs)),
			humanize.IBytes(uint64(tx)), humanize.IBytes(uint64(txs)),
		)
	case "sp-info":
		nice, err := NicenessParse(sds["nice"])
		if err != nil {
			return s
		}
		msg = fmt.Sprintf(
			"Packet %s (%s) (nice %s)",
			sds["hash"],
			size,
			NicenessFmt(nice),
		)
		offsetParsed, err := strconv.ParseUint(sds["offset"], 10, 64)
		if err != nil {
			return s
		}
		sizeParsed, err := strconv.ParseUint(sds["size"], 10, 64)
		if err != nil {
			return s
		}
		msg += fmt.Sprintf(": %d%%", 100*offsetParsed/sizeParsed)
		if len(rem) > 0 {
			msg += ": " + rem
		}
	case "sp-infos":
		switch sds["xx"] {
		case "rx":
			msg = fmt.Sprintf("%s has got for us: ", nodeS)
		case "tx":
			msg = fmt.Sprintf("We have got for %s: ", nodeS)
		default:
			return s
		}
		msg += fmt.Sprintf("%s packets, %s", sds["pkts"], size)
	case "sp-process":
		msg = fmt.Sprintf("%s has %s (%s): %s", nodeS, sds["hash"], size, rem)
	case "sp-file":
		switch sds["xx"] {
		case "rx":
			msg = "Got packet "
		case "tx":
			msg = "Sent packet "
		default:
			return s
		}
		fullsize, err := strconv.ParseUint(sds["fullsize"], 10, 64)
		if err != nil {
			return s
		}
		sizeParsed, err := strconv.ParseUint(sds["size"], 10, 64)
		if err != nil {
			return s
		}
		msg += fmt.Sprintf(
			"%s %d%% (%s / %s)",
			sds["hash"],
			100*sizeParsed/fullsize,
			humanize.IBytes(uint64(sizeParsed)),
			humanize.IBytes(uint64(fullsize)),
		)
	case "sp-done":
		switch sds["xx"] {
		case "rx":
			msg = fmt.Sprintf("Packet %s is retreived (%s)", sds["hash"], size)
		case "tx":
			msg = fmt.Sprintf("Packet %s is sent", sds["hash"])
		default:
			return s
		}
	case "nncp-reass":
		chunkNum, exists := sds["chunk"]
		if exists {
			msg = fmt.Sprintf(
				"Reassembling chunked file \"%s\" (chunk %s): %s",
				sds["path"],
				chunkNum,
				rem,
			)
		} else {
			msg = fmt.Sprintf(
				"Reassembling chunked file \"%s\": %s",
				sds["path"],
				rem,
			)
		}
		if err, exists := sds["err"]; exists {
			msg += ": " + err
		}
	case "lockdir":
		msg = fmt.Sprintf("Acquire lock for %s: %s", sds["path"], sds["err"])
	default:
		return s
	}
	return fmt.Sprintf("%s %s%s", when.Format(time.RFC3339), level, msg)
}
