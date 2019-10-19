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
	"log"
	"strings"
)

// Helper function for parsing -via command line option
func ViaOverride(argValue string, ctx *Ctx, node *Node) {
	if argValue == "" {
		return
	}
	if argValue == "-" {
		node.Via = make([]*NodeId, 0)
		return
	}
	vias := make([]*NodeId, 0, strings.Count(argValue, ",")+1)
	for _, via := range strings.Split(argValue, ",") {
		foundNodeId, err := ctx.FindNode(via)
		if err != nil {
			log.Fatalln("Invalid Via node specified:", err)
		}
		vias = append(vias, foundNodeId.Id)
	}
	node.Via = vias
}
