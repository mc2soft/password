package password

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var ab64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./").WithPadding(base64.NoPadding)

const alg = "pbkdf2-sha512"

func GenerateSalt(size int) ([]byte, error) {
	if size < 16 {
		return nil, errors.New("will not generate too little salt")
	}
	b := make([]byte, size)
	now := uint64(time.Now().UnixNano())
	binary.BigEndian.PutUint64(b, now)
	_, err := io.ReadFull(rand.Reader, b[8:])
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Encrypt(password string, rounds int, salt []byte) Password {
	b := key([]byte(password), salt, rounds, sha512.Size, sha512.New)
	return Password(fmt.Sprintf("$%s$%d$%s$%s", alg, rounds, ab64.EncodeToString(salt), ab64.EncodeToString(b)))
}

type Password string

func (p Password) Split() (rounds int, salt []byte, hash []byte) {
	parts := strings.Split(string(p), "$")
	if parts[0] != "" || parts[1] != alg {
		panic("unexpected algorithm")
	}
	var err error
	rounds, err = strconv.Atoi(parts[2])
	if err != nil {
		panic(err)
	}
	salt, err = ab64.DecodeString(parts[3])
	if err != nil {
		panic(err)
	}
	hash, err = ab64.DecodeString(parts[4])
	if err != nil {
		panic(err)
	}
	return
}

func (p Password) Rounds() int {
	r, _, _ := p.Split()
	return r
}

func (p Password) Salt() []byte {
	_, s, _ := p.Split()
	return s
}

func (p Password) Verify(password string) bool {
	r, s, h1 := p.Split()
	_, _, h2 := Encrypt(password, r, s).Split()
	return subtle.ConstantTimeCompare(h1, h2) == 1
}

// TODO Verify without downgrade
