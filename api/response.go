package api

import (
	"errors"

	"github.com/go-resty/resty/v2"
)

// NilResponse reports a usable error when resty returns no Response.
// Callers must use this before StatusCode: a nil *resty.Response panics,
// and Execute can return that together with a nil or non-nil error.
func NilResponse(res *resty.Response, err error) error {
	if res != nil {
		return nil
	}
	if err == nil {
		err = errors.New("nil http response")
	}
	return err
}
