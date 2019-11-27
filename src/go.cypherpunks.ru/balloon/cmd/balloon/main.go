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

package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"go.cypherpunks.ru/balloon"
)

func main() {
	s := flag.Int("s", 1<<16, "Space cost, number of hash-sized blocks")
	t := flag.Int("t", 3, "Time cost, rounds")
	p := flag.Int("p", 1, "Number of threads")
	saltHex := flag.String("salt", "", "Salt, hexadecimal, optional")
	passwd := flag.String("passwd", "", "Password")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "balloon -- Strengthen password with Balloon+SHA512\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	var salt []byte
	var err error
	if len(*saltHex) == 0 {
		salt = make([]byte, 8)
		_, err = io.ReadFull(rand.Reader, salt)
	} else {
		salt, err = hex.DecodeString(*saltHex)
	}
	if err != nil {
		panic(err)
	}
	fmt.Println("Salt:", hex.EncodeToString(salt))
	h := balloon.H(sha512.New, []byte(*passwd), salt, *s, *t, *p)
	fmt.Println("Hash:", hex.EncodeToString(h))
	fmt.Printf(
		"Encoded: $balloon$h=sha512,s=%d,t=%d,p=%d$%s$%s\n",
		*s, *t, *p,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h),
	)
}
