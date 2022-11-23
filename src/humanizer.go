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
	"strings"
	"time"

	"go.cypherpunks.ru/recfile"
)

func (ctx *Ctx) HumanizeRec(rec string) string {
	r := recfile.NewReader(strings.NewReader(rec))
	le, err := r.NextMap()
	if err != nil {
		return rec
	}
	humanized, err := ctx.Humanize(le)
	if err != nil {
		return fmt.Sprintf("Can not humanize: %s\n%s", err, rec)
	}
	return humanized
}

func (ctx *Ctx) Humanize(le map[string]string) (string, error) {
	when, err := time.Parse(time.RFC3339Nano, le["When"])
	if err != nil {
		return "", err
	}
	var level string
	msg := le["Msg"]
	if errMsg, isErr := le["Err"]; isErr {
		level = "ERROR "
		msg += ": " + errMsg
	}
	return fmt.Sprintf("%s %s%s", when.Format(time.RFC3339), level, msg), nil
}
