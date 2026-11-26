package protocols

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nfsSupportsTimeUpdates = true

func (files nfsFiles) openTimeTarget(name string) (*os.File, error) {
	return files.open(name, unix.O_PATH|unix.O_NOFOLLOW)
}

func (files nfsFiles) readlink(name string, info fs.FileInfo) (string, fs.FileInfo, error) {
	file, err := files.openTimeTarget(name)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", nil, err
	}
	if !os.SameFile(opened, info) {
		return "", nil, unix.ESTALE
	}
	limit := int(files.transfer) + 1
	for size := min(256, limit); ; size = min(size*2, limit) {
		target := make([]byte, size)
		n, err := unix.Readlinkat(int(file.Fd()), "", target)
		if err != nil {
			return "", opened, err
		}
		if n < size {
			after, _ := file.Stat()
			return string(target[:n]), after, nil
		}
		if size == limit {
			return "", opened, unix.ENAMETOOLONG
		}
	}
}

func (files nfsFiles) access(name string, info fs.FileInfo, requested uint32) (uint32, error) {
	file, err := files.openTimeTarget(name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, opened) {
		return 0, fs.ErrNotExist
	}
	fd := int(file.Fd())
	return nfsAccessMask(opened, requested, func(permission uint32) (bool, error) {
		err := unix.Faccessat2(fd, "", permission, unix.AT_EACCESS|unix.AT_EMPTY_PATH)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			err = unix.Faccessat(unix.AT_FDCWD, nfsDescriptorPath(fd), permission, unix.AT_EACCESS)
		}
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, unix.EROFS) {
			return false, nil
		}
		return err == nil, err
	})
}

func nfsSetFileTimes(file *os.File, requested [2]nfsSetTime) error {
	var times [2]unix.Timespec
	for i, stamp := range requested {
		switch stamp.how {
		case nfsTimeUnchanged:
			times[i].Nsec = unix.UTIME_OMIT
		case nfsTimeServer:
			times[i].Nsec = unix.UTIME_NOW
		case nfsTimeClient:
			times[i] = unix.NsecToTimespec(int64(stamp.seconds)*1_000_000_000 + int64(stamp.nanoseconds))
			if int64(times[i].Sec) != int64(stamp.seconds) {
				return unix.EOVERFLOW
			}
		}
	}
	return unix.UtimesNanoAt(int(file.Fd()), "", times[:], unix.AT_EMPTY_PATH)
}

func nfsFileTimes(info fs.FileInfo) (accessed, changed time.Time) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec)),
			time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	}
	return info.ModTime(), info.ModTime()
}

func (files nfsFiles) openAttributes(name string, flags int) (*os.File, error) {
	return files.open(name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK)
}

func (files nfsFiles) removeEntry(directory, name string, parent fs.FileInfo, removeDir bool) error {
	dir, err := files.open(directory, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, parent) {
		return unix.ESTALE
	}
	flags := 0
	if removeDir {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(int(dir.Fd()), name, flags)
}

func (files nfsFiles) renameEntry(source, destination string, parent, destinationParent fs.FileInfo) (fs.FileInfo, fs.FileInfo, error) {
	from, err := files.openRenameDirectory(path.Dir(source), parent)
	if err != nil {
		return nil, nil, err
	}
	defer from.Close()
	to, err := files.openRenameDirectory(path.Dir(destination), destinationParent)
	if err != nil {
		after, _ := from.Stat()
		return after, nil, err
	}
	defer to.Close()

	err = unix.Renameat(int(from.Fd()), path.Base(source), int(to.Fd()), path.Base(destination))
	after, _ := from.Stat()
	destinationAfter, _ := to.Stat()
	return after, destinationAfter, err
}

func (files nfsFiles) openRenameDirectory(name string, expected fs.FileInfo) (*os.File, error) {
	dir, err := files.open(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY)
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, fs.ErrNotExist) {
		return nil, unix.ESTALE
	}
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err == nil && !os.SameFile(info, expected) {
		err = unix.ESTALE
	}
	if err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func (files nfsFiles) statfs(name string, info fs.FileInfo) (unix.Statfs_t, error) {
	var stats unix.Statfs_t
	file, err := files.open(name, unix.O_PATH|unix.O_NOFOLLOW)
	if err != nil {
		return stats, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return stats, err
	}
	if !os.SameFile(info, opened) {
		return stats, fs.ErrNotExist
	}
	err = unix.Fstatfs(int(file.Fd()), &stats)
	return stats, err
}

func (files nfsFiles) filesystemStats(name string, info fs.FileInfo) ([6]uint64, error) {
	stats, err := files.statfs(name, info)
	if err != nil {
		return [6]uint64{}, err
	}
	blockSize := stats.Frsize
	if blockSize == 0 {
		blockSize = stats.Bsize
	}
	return [6]uint64{
		stats.Blocks * uint64(blockSize), stats.Bfree * uint64(blockSize),
		stats.Bavail * uint64(blockSize), stats.Files, stats.Ffree, stats.Ffree,
	}, nil
}

func (files nfsFiles) pathLimits(name string, info fs.FileInfo) (nameMax, linkMax, caseInsensitive uint32, err error) {
	stats, err := files.statfs(name, info)
	if err != nil {
		return 0, 0, 0, err
	}
	if stats.Namelen <= 0 {
		return 0, 0, 0, fs.ErrInvalid
	}
	linkMax = 8 // POSIX minimum on filesystems that support hard links.
	switch stats.Type {
	case unix.MSDOS_SUPER_MAGIC:
		linkMax = 1
	case unix.EXFAT_SUPER_MAGIC:
		linkMax = 1
		caseInsensitive = 1
	}
	return uint32(stats.Namelen), linkMax, caseInsensitive, nil
}

func (files nfsFiles) filesystemCapabilities(name string, info fs.FileInfo) (uint64, uint32, error) {
	stats, err := files.statfs(name, info)
	if err != nil {
		return 0, 0, err
	}
	switch stats.Type {
	case unix.MSDOS_SUPER_MAGIC:
		return math.MaxUint32, 0, nil
	case unix.EXFAT_SUPER_MAGIC:
		return math.MaxInt64, 0, nil
	default:
		properties := uint32(nfsFSInfoSymlink | nfsFSInfoLink)
		if stats.Flags&unix.ST_RDONLY == 0 {
			properties |= nfsFSInfoCanSetTime
		}
		return math.MaxInt64, properties, nil
	}
}

func (files nfsFiles) hardLink(source, directory, child string, info, parent fs.FileInfo) (fs.FileInfo, error) {
	file, err := files.openTimeTarget(source)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, unix.ESTALE
	}
	dir, err := files.open(directory, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	directoryInfo, err := dir.Stat()
	if err != nil || !os.SameFile(parent, directoryInfo) {
		return nil, unix.ESTALE
	}
	var stats unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &stats); err != nil {
		return nil, err
	}
	if stats.Type == unix.MSDOS_SUPER_MAGIC || stats.Type == unix.EXFAT_SUPER_MAGIC {
		return nil, errors.ErrUnsupported
	}
	if err := nfsLinkDescriptor(int(file.Fd()), int(dir.Fd()), path.Base(child)); err != nil {
		return nil, err
	}
	updated, _ := file.Stat()
	return updated, nil
}

func nfsFileOwner(info fs.FileInfo) (links, uid, gid uint32) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint32(stat.Nlink), stat.Uid, stat.Gid
	}
	return 1, 0, 0
}

func nfsFileIdentity(info fs.FileInfo) (filesystemID, fileID uint64) {
	if info != nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return uint64(stat.Dev), stat.Ino
		}
	}
	return 0, 0
}
