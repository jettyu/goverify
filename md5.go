package goverify

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	//MD5VerifyError ...
	MD5VerifyError = errors.New("md5 verify failed")
)

var (
	_ Interface = Md5Sign{}
)

// Md5Sign sign with md5
type Md5Sign struct {
	key string
}

// NewMd5Sign ...
func NewMd5Sign(key string) Md5Sign {
	return Md5Sign{key}
}

// Sign ...
func (p Md5Sign) Sign(data string) (string, error) {
	md5Sum := md5.Sum([]byte(data + fmt.Sprint("&key=", p.key)))
	return base64.StdEncoding.EncodeToString(md5Sum[:]), nil
}

// Verify ...
func (p Md5Sign) Verify(data, sign string) error {
	s, _ := p.Sign(data)
	if sign == s {
		return nil
	}
	return MD5VerifyError
}
