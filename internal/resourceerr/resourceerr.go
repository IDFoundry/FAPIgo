// Package resourceerr lets the packages of this module that answer for
// a protected resource classify store failures the same way resource
// does, and build a *resource.Error that keeps its cause, without
// adding either to resource's exported API.
package resourceerr

import (
	"context"
	"errors"

	"github.com/idfoundry/fapigo/storage"
)

// StoreUnavailable reports whether err is a store failing to answer
// rather than answering no: it wraps storage.ErrStoreUnavailable, or a
// cancelled or timed-out context.
func StoreUnavailable(err error) bool {
	return errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// NewWithCause builds a *resource.Error with code, httpStatus and
// description, whose Unwrap returns cause. Package resource sets it when
// it is initialised, so it is always set for a package that imports
// resource.
var NewWithCause func(code string, httpStatus int, description string, cause error) error
