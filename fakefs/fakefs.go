package fakefs

import "github.com/spf13/afero"

type Fs struct {
	afero.Fs
}

func NewMemMapFs() *Fs {
	return &Fs{
		Fs: afero.NewMemMapFs(),
	}
}
