package protocols

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const nfsCreateVerifierAttr = "user.protosim.nfs.createverf"

func (files nfsFiles) createExclusive(directory, name string, parent fs.FileInfo, verifier []byte) (fs.FileInfo, error) {
	dir, err := files.openAttributes(directory, os.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(parent, opened) {
		return nil, fs.ErrNotExist
	}
	dirFD := int(dir.Fd())
	if info, err := nfsReplayExclusive(dir, name, verifier); !errors.Is(err, fs.ErrNotExist) {
		return info, err
	}

	// Persist the verifier before publishing a name for the new inode.
	fd, err := unix.Openat(dirFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, nfsExclusiveStorageError(err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := unix.Fsetxattr(fd, nfsCreateVerifierAttr, verifier, unix.XATTR_CREATE); err != nil {
		return nil, nfsExclusiveStorageError(err)
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}

	err = nfsLinkDescriptor(fd, dirFD, name)
	if errors.Is(err, fs.ErrExist) {
		return nfsReplayExclusive(dir, name, verifier)
	}
	if err != nil {
		return nil, err
	}
	if err := dir.Sync(); err != nil {
		return nil, err
	}
	return file.Stat()
}

func nfsReplayExclusive(dir *os.File, name string, verifier []byte) (fs.FileInfo, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrExist
	}
	var stored [8]byte
	n, err := unix.Getxattr(nfsDescriptorPath(fd), nfsCreateVerifierAttr, stored[:])
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ERANGE), errors.Is(err, fs.ErrPermission):
		return nil, fs.ErrExist
	case errors.Is(err, fs.ErrNotExist):
		return nil, errors.ErrUnsupported
	case err != nil:
		return nil, nfsExclusiveStorageError(err)
	case n != len(stored) || !bytes.Equal(verifier, stored[:]):
		return nil, fs.ErrExist
	}
	if err := dir.Sync(); err != nil {
		return nil, err
	}
	return info, nil
}

func nfsDescriptorPath(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

func nfsLinkDescriptor(fd, dirFD int, name string) error {
	err := unix.Linkat(fd, "", dirFD, name, unix.AT_EMPTY_PATH)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) {
		// AT_EMPTY_PATH requires a capability that ordinary server users lack.
		return unix.Linkat(unix.AT_FDCWD, nfsDescriptorPath(fd), dirFD, name, unix.AT_SYMLINK_FOLLOW)
	}
	return err
}

func nfsExclusiveStorageError(err error) error {
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("%w: %v", errors.ErrUnsupported, err)
	}
	return err
}
