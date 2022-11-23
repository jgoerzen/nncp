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
)

type Magic struct {
	B    [8]byte
	Name string
	Till string
}

var (
	MagicNNCPAv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'A', 0, 0, 1},
		Name: "NNCPAv1 (area packet v1)", Till: "now",
	}
	MagicNNCPBv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 1},
		Name: "NNCPBv1 (EBlob v1)", Till: "1.0",
	}
	MagicNNCPBv2 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 2},
		Name: "NNCPBv2 (EBlob v2)", Till: "3.4",
	}
	MagicNNCPBv3 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 3},
		Name: "NNCPBv3 (EBlob v3)", Till: "now",
	}
	MagicNNCPDv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'D', 0, 0, 1},
		Name: "NNCPDv1 (multicast discovery v1)", Till: "now",
	}
	MagicNNCPEv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 1},
		Name: "NNCPEv1 (encrypted packet v1)", Till: "0.12",
	}
	MagicNNCPEv2 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 2},
		Name: "NNCPEv2 (encrypted packet v2)", Till: "1.0",
	}
	MagicNNCPEv3 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 3},
		Name: "NNCPEv3 (encrypted packet v3)", Till: "3.4",
	}
	MagicNNCPEv4 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 4},
		Name: "NNCPEv4 (encrypted packet v4)", Till: "6.6.0",
	}
	MagicNNCPEv5 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 5},
		Name: "NNCPEv5 (encrypted packet v5)", Till: "7.7.0",
	}
	MagicNNCPEv6 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 6},
		Name: "NNCPEv6 (encrypted packet v6)", Till: "now",
	}
	MagicNNCPSv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'S', 0, 0, 1},
		Name: "NNCPSv1 (sync protocol v1)", Till: "now",
	}
	MagicNNCPMv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'M', 0, 0, 1},
		Name: "NNCPMv1 (chunked .meta v1)", Till: "6.6.0",
	}
	MagicNNCPMv2 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'M', 0, 0, 2},
		Name: "NNCPMv2 (chunked .meta v2)", Till: "now",
	}
	MagicNNCPPv1 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 1},
		Name: "NNCPPv1 (plain packet v1)", Till: "2.0",
	}
	MagicNNCPPv2 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 2},
		Name: "NNCPPv2 (plain packet v2)", Till: "4.1",
	}
	MagicNNCPPv3 = Magic{
		B:    [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 3},
		Name: "NNCPPv3 (plain packet v3)", Till: "now",
	}

	BadMagic error = errors.New("Unknown magic number")
)

func (m *Magic) TooOld() error {
	return fmt.Errorf("%s format is unsupported (used till %s)", m.Name, m.Till)
}
