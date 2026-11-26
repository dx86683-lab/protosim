//go:build !linux

package protocols

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path"
	"syscall"
	"time"
)

const nfsSupportsTimeUpdates = false

func (nfsFiles) access(_ string, info fs.FileInfo, requested uint32) (uint32, error) {
	ownerPermissions := uint32(info.Mode().Perm() >> 6)
	return nfsAccessMask(info, requested, func(permission uint32) (bool, error) {
		return ownerPermissions&permission == permission, nil
	})
}

func (nfsFiles) createExclusive(string, string, fs.FileInfo, []byte) (fs.FileInfo, error) {
	return nil, errors.ErrUnsupported
}

func (files nfsFiles) openTimeTarget(string) (*os.File, error) {
	return nil, errors.ErrUnsupported
}

func (files nfsFiles) readlink(name string, info fs.FileInfo) (string, fs.FileInfo, error) {
	target, err := files.root.Readlink(name)
	if err != nil {
		return "", info, err
	}
	after, err := files.stat(name)
	if err != nil {
		return "", nil, err
	}
	if !os.SameFile(after, info) {
		return "", nil, syscall.ESTALE
	}
	if len(target) > int(files.transfer) {
		return "", after, syscall.ENAMETOOLONG
	}
	return target, after, nil
}

func nfsSetFileTimes(*os.File, [2]nfsSetTime) error {
	return errors.ErrUnsupported
}

func nfsFileTimes(info fs.FileInfo) (accessed, changed time.Time) {
	return info.ModTime(), info.ModTime()
}

func (files nfsFiles) openAttributes(name string, flags int) (*os.File, error) {
	return files.open(name, flags)
}

func (files nfsFiles) renameEntry(source, destination string, parent, destinationParent fs.FileInfo) (fs.FileInfo, fs.FileInfo, error) {
	fromDir, toDir := path.Dir(source), path.Dir(destination)
	from, fromErr := files.stat(fromDir)
	to, toErr := files.stat(toDir)
	if fromErr != nil || toErr != nil || !os.SameFile(from, parent) || !os.SameFile(to, destinationParent) {
		return nil, nil, syscall.ESTALE
	}
	err := files.root.Rename(source, destination)
	after, _ := files.stat(fromDir)
	destinationAfter, _ := files.stat(toDir)
	return after, destinationAfter, err
}

func (files nfsFiles) removeEntry(directory, name string, parent fs.FileInfo, removeDir bool) error {
	dir, err := files.openDir(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(info, parent) {
		return syscall.ESTALE
	}
	child, err := dir.Lstat(name)
	if err != nil {
		return err
	}
	switch {
	case child.IsDir() && !removeDir:
		return syscall.EISDIR
	case !child.IsDir() && removeDir:
		return syscall.ENOTDIR
	}
	err = dir.Remove(name)
	if removeDir && errors.Is(err, fs.ErrExist) {
		return syscall.ENOTEMPTY
	}
	return err
}

func (nfsFiles) filesystemStats(string, fs.FileInfo) ([6]uint64, error) {
	return [6]uint64{}, fs.ErrInvalid
}

func (nfsFiles) pathLimits(string, fs.FileInfo) (nameMax, linkMax, caseInsensitive uint32, err error) {
	return 255, 1, 0, nil
}

func (nfsFiles) hardLink(string, string, string, fs.FileInfo, fs.FileInfo) (fs.FileInfo, error) {
	return nil, errors.ErrUnsupported
}

func (nfsFiles) filesystemCapabilities(string, fs.FileInfo) (uint64, uint32, error) {
	return math.MaxInt64, nfsFSInfoSymlink, nil
}

func nfsFileOwner(fs.FileInfo) (links, uid, gid uint32) {
	return 1, 0, 0
}

func nfsFileIdentity(fs.FileInfo) (filesystemID, fileID uint64) {
	return 0, 0
}
