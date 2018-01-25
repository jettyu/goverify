package goverify_test

import (
	"testing"

	"github.com/jettyu/goverify"
)

func TestMd5(t *testing.T) {
	key := "123456"
	data := "test"
	sign, _ := goverify.NewMd5Sign(key).Sign(data)

	if err := goverify.NewMd5Sign(key).Verify(data, sign); err != nil {
		t.Error(err)
	}
}
