/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
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
	"os"
	"os/exec"
	"time"
)

type PipeConn struct {
	cmd *exec.Cmd
	r   *os.File
	w   *os.File
}

func NewPipeConn(command string) (ConnDeadlined, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdin = stdinR
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = stdoutW
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	return &PipeConn{cmd, stdoutR, stdinW}, nil
}

func (c PipeConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c PipeConn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c PipeConn) SetReadDeadline(t time.Time) error {
	return c.r.SetReadDeadline(t)
}

func (c PipeConn) SetWriteDeadline(t time.Time) error {
	return c.w.SetWriteDeadline(t)
}

func (c PipeConn) Close() (err error) {
	err = c.w.Close()
	go c.cmd.Wait()
	time.AfterFunc(time.Duration(10*time.Second), func() { c.cmd.Process.Kill() })
	return
}
