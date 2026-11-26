package goutils

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
)

func GetFileName() string {
	_, fpath, _, ok := runtime.Caller(1)
	if !ok {
		err := errors.New("failed to get filename")
		panic(err)
	}

	return strings.TrimSuffix(filepath.Base(fpath), filepath.Ext(fpath))
}
