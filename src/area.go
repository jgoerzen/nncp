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
)

const AreaDir = "area"

var (
	PktAreaOverhead int64
)

type AreaId [32]byte

func (id AreaId) String() string {
	return Base32Codec.EncodeToString(id[:])
}

type Area struct {
	Name string
	Id   *AreaId
	Pub  *[32]byte
	Prv  *[32]byte

	Subs []*NodeId

	Exec     map[string][]string
	Incoming *string

	AllowUnknown bool
}

func AreaIdFromString(raw string) (*AreaId, error) {
	idRaw, err := Base32Codec.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(idRaw) != 32 {
		return nil, errors.New("Invalid area id size")
	}
	areaId := new(AreaId)
	copy(areaId[:], idRaw)
	return areaId, nil
}

func (ctx *Ctx) AreaName(id *AreaId) string {
	area := ctx.AreaId2Area[*id]
	if area == nil {
		return id.String()
	}
	return area.Name
}
