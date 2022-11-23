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
	"os"
	"time"
)

const UCSPITCPClient = "UCSPI-TCP-CLIENT"

type UCSPIConn struct {
	R *os.File
	W *os.File
}

func (c UCSPIConn) Read(p []byte) (n int, err error) {
	return c.R.Read(p)
}

func (c UCSPIConn) Write(p []byte) (n int, err error) {
	return c.W.Write(p)
}

func (c UCSPIConn) SetReadDeadline(t time.Time) error {
	return c.R.SetReadDeadline(t)
}

func (c UCSPIConn) SetWriteDeadline(t time.Time) error {
	return c.W.SetWriteDeadline(t)
}

func (c UCSPIConn) Close() error {
	if err := c.R.Close(); err != nil {
		c.W.Close()
		return err
	}
	return c.W.Close()
}

func UCSPITCPRemoteAddr() (addr string) {
	if proto := os.Getenv("PROTO"); proto == "TCP" {
		port := os.Getenv("TCPREMOTEPORT")
		if host := os.Getenv("TCPREMOTEHOST"); host == "" {
			addr = fmt.Sprintf("[%s]:%s", os.Getenv("TCPREMOTEIP"), port)
		} else {
			addr = fmt.Sprintf("%s:%s", host, port)
		}
	}
	return
}
