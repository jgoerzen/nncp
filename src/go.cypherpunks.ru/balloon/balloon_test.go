/*
balloon -- Balloon password hashing function
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this program.  If not, see
<http://www.gnu.org/licenses/>.
*/

package balloon

import (
	"crypto/rand"
	"crypto/sha512"
	"testing"
	"testing/quick"
)

func TestB(t *testing.T) {
	f := func(passwd, salt []byte, s, t uint8) bool {
		if len(passwd) == 0 || len(salt) == 0 {
			return true
		}
		B(sha512.New(), passwd, salt, uint64(s)%16+1, uint64(t)%16+1)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestH(t *testing.T) {
	f := func(passwd, salt []byte, s, t, p uint8) bool {
		if len(passwd) == 0 || len(salt) == 0 {
			return true
		}
		H(sha512.New, passwd, salt, int(s)%16+1, int(t)%16+1, int(p)%8+1)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func BenchmarkB(b *testing.B) {
	passwd := make([]byte, 8)
	rand.Read(passwd)
	salt := make([]byte, 8)
	rand.Read(salt)
	h := sha512.New()
	sCost := uint64(1 << 10 / h.Size())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		B(h, passwd, salt, sCost, 4)
	}
}

func BenchmarkH(b *testing.B) {
	passwd := make([]byte, 8)
	rand.Read(passwd)
	salt := make([]byte, 8)
	rand.Read(salt)
	sCost := 1 << 10 / sha512.New().Size()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		H(sha512.New, passwd, salt, sCost, 4, 4)
	}
}
