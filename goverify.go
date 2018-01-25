// Package sign ...
// sign  and verify with go
package goverify

// Interface ...
type Interface interface {
	Sign(data string) (string, error)
	Verify(data, sign string) error
}
