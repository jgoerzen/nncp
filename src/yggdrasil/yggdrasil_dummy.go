//go:build noyggdrasil
// +build noyggdrasil

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

package yggdrasil

import (
	"errors"
	"net"
)

var NoYggdrasil = errors.New("no Yggdrasil support is compiled in")

func NewConn(aliases map[string]string, in string) (ConnDeadlined, error) {
	return nil, NoYggdrasil

}

func NewListener(aliases map[string]string, in string) (net.Listener, error) {
	return nil, NoYggdrasil
}
