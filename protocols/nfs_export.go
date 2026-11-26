package protocols

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strings"
	"syscall"
)

const (
	nfs3ErrPerm         = 1
	nfs3ErrNoEnt        = 2
	nfs3ErrIO           = 5
	nfs3ErrAccess       = 13
	nfs3ErrExist        = 17
	nfs3ErrCrossDevice  = 18
	nfs3ErrNotDir       = 20
	nfs3ErrIsDir        = 21
	nfs3ErrInvalid      = 22
	nfs3ErrFileTooBig   = 27
	nfs3ErrNoSpace      = 28
	nfs3ErrReadOnly     = 30
	nfs3ErrTooManyLinks = 31
	nfs3ErrNameTooLong  = 63
	nfs3ErrNotEmpty     = 66
	nfs3ErrStale        = 70
	nfs3ErrBadCookie    = 10003
	nfs3ErrNotSupp      = 10004
	nfs3ErrTooSmall     = 10005
	nfs3ErrServerFault  = 10006
	nfs3ErrNotSync      = 10002
)

func nfsWords(values ...uint32) []byte {
	wire := make([]byte, 0, 4*len(values))
	for _, value := range values {
		wire = binary.BigEndian.AppendUint32(wire, value)
	}
	return wire
}

func nfsOpaque(wire, value []byte) []byte {
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(value)))
	wire = append(wire, value...)
	return append(wire, make([]byte, (-len(value))&3)...)
}

func takeNFSOpaque(wire *[]byte) ([]byte, bool) {
	if len(*wire) < 4 {
		return nil, false
	}
	length := binary.BigEndian.Uint32(*wire)
	if length > uint32(len(*wire)-4) {
		return nil, false
	}
	padded := (int(length) + 3) &^ 3
	if padded > len(*wire)-4 {
		return nil, false
	}
	value := (*wire)[4 : 4+int(length)]
	*wire = (*wire)[4+padded:]
	return value, true
}

func nfsReplyError(procedure, status uint32) []byte {
	switch procedure {
	case 3, 4, 5, 6, 16, 17, 18, 19, 20:
		return nfsWords(status, 0) // absent post-operation attributes
	case 2, 7, 8, 9, 10, 11, 12, 13, 21:
		return nfsWords(status, 0, 0) // absent before and after attributes
	case 14:
		return nfsWords(status, 0, 0, 0, 0)
	case 15:
		return nfsWords(status, 0, 0, 0)
	default:
		return nfsWords(status)
	}
}

const (
	nfsFSInfoLink       = 0x01
	nfsFSInfoSymlink    = 0x02
	nfsFSInfoCanSetTime = 0x10
)

func (server *nfsServer) fileReply(procedure uint32, export string, args []byte, transfer uint32) []byte {
	if procedure == 11 { // MKNOD
		return nfsReplyError(procedure, nfs3ErrNotSupp)
	}
	if len(args) <= 4 {
		return nfsReplyError(procedure, nfs3ErrInvalid)
	}
	handle, handleOK := takeNFSOpaque(&args)
	var lookupName []byte
	switch procedure {
	case 3: // LOOKUP decodes the name before resolving the handle.
		var ok bool
		lookupName, ok = takeNFSOpaque(&args)
		if !handleOK || !ok {
			return nfsReplyError(procedure, nfs3ErrInvalid)
		}
	case 6: // READ
		if !handleOK || len(args) < 12 {
			return nfsReplyError(procedure, nfs3ErrInvalid)
		}
	case 16: // READDIR
		if !handleOK || len(args) < 20 {
			return nfsReplyError(procedure, nfs3ErrInvalid)
		}
	case 17: // READDIRPLUS
		if !handleOK || len(args) < 24 {
			return nfsReplyError(procedure, nfs3ErrInvalid)
		}
	}
	if !handleOK {
		return nfsReplyError(procedure, nfs3ErrStale)
	}
	root, err := os.OpenRoot(export)
	if err != nil {
		return nfsReplyError(procedure, nfs3ErrStale)
	}
	defer root.Close()
	files := nfsFiles{root: root, transfer: transfer}
	name, info, statErr := server.resolveHandle(handle, files)
	if name == "" {
		return nfsReplyError(procedure, nfs3ErrStale)
	}
	post := nfsPostAttr(nfsWords(0), info)
	switch procedure {
	case 1: // GETATTR
		if statErr != nil {
			return nfsWords(nfsFileError(statErr))
		}
		return nfsAttr(nfsWords(0), info)
	case 2: // SETATTR
		return files.setAttr(name, info, statErr, args)
	case 3: // LOOKUP
		return server.lookup(files, name, info, string(lookupName))
	case 4: // ACCESS
		if len(args) != 4 {
			return nfsReplyError(procedure, nfs3ErrInvalid)
		}
		if statErr != nil {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		allowed, err := files.access(name, info, binary.BigEndian.Uint32(args))
		if errors.Is(err, fs.ErrNotExist) {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		if err != nil {
			return nfsPostAttr(nfsWords(nfs3ErrServerFault), info)
		}
		return binary.BigEndian.AppendUint32(post, allowed)
	case 5: // READLINK
		if statErr != nil {
			return nfsReplyError(procedure, nfsFileError(statErr))
		}
		if len(args) != 0 || info.Mode()&fs.ModeSymlink == 0 {
			return nfsPostAttr(nfsWords(nfs3ErrInvalid), info)
		}
		target, after, err := files.readlink(name, info)
		if err != nil {
			return nfsPostAttr(nfsWords(nfsFileError(err)), after)
		}
		return nfsOpaque(nfsPostAttr(nfsWords(0), after), []byte(target))
	case 6: // READ
		return files.read(name, info, statErr, args)
	case 7: // WRITE
		return server.write(files, name, info, statErr, args)
	case 8, 9, 10: // CREATE, MKDIR, SYMLINK
		return server.create(procedure, files, name, info, args)
	case 12, 13: // REMOVE and RMDIR
		return server.remove(procedure, files, name, info, statErr, args)
	case 14: // RENAME
		return server.rename(files, name, info, statErr, args)
	case 15: // LINK
		return server.link(files, name, info, statErr, args)
	case 16, 17: // READDIR and READDIRPLUS
		return server.readDir(procedure, files, name, handle, info, args, post)
	case 18: // FSSTAT
		if statErr != nil {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		stats, err := files.filesystemStats(name, info)
		if err != nil {
			return nfsPostAttr(nfsWords(nfs3ErrIO), info)
		}
		for _, value := range stats {
			post = binary.BigEndian.AppendUint64(post, value)
		}
		return binary.BigEndian.AppendUint32(post, 0)
	case 19: // FSINFO
		if statErr != nil {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		maxFileSize, properties, err := files.filesystemCapabilities(name, info)
		if errors.Is(err, fs.ErrNotExist) {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		if err != nil {
			return nfsPostAttr(nfsWords(nfs3ErrServerFault), info)
		}
		post = append(post, nfsWords(transfer, transfer, 4096, transfer, transfer, 4096, min(8192, transfer-1024))...)
		post = binary.BigEndian.AppendUint64(post, maxFileSize)
		if properties&nfsFSInfoCanSetTime != 0 {
			return append(post, nfsWords(1, 0, properties)...)
		}
		return append(post, nfsWords(0, 1, properties)...)
	case 20: // PATHCONF
		if statErr != nil {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		nameMax, linkMax, caseInsensitive, err := files.pathLimits(name, info)
		if errors.Is(err, fs.ErrNotExist) {
			return nfsReplyError(procedure, nfs3ErrStale)
		}
		if err != nil {
			return nfsPostAttr(nfsWords(nfs3ErrServerFault), info)
		}
		return append(post, nfsWords(linkMax, nameMax, 1, 1, caseInsensitive, 1)...)
	case 21: // COMMIT
		return server.commit(files, name, info, statErr, args)
	default:
		return nfsWords(nfs3ErrStale)
	}
}

type nfsFiles struct {
	root     *os.Root
	transfer uint32
}

func (files nfsFiles) stat(name string) (fs.FileInfo, error) {
	return files.root.Lstat(name)
}

func (files nfsFiles) open(name string, flags int) (*os.File, error) {
	return files.root.OpenFile(name, flags, 0)
}

func (files nfsFiles) openDir(name string) (*os.Root, error) {
	return files.root.OpenRoot(name)
}

func nfsFileError(err error) uint32 {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nfs3ErrNoEnt
	case errors.Is(err, fs.ErrPermission):
		return nfs3ErrAccess
	case errors.Is(err, syscall.ENOTEMPTY):
		return nfs3ErrNotEmpty
	case errors.Is(err, fs.ErrExist):
		return nfs3ErrExist
	case errors.Is(err, syscall.EXDEV):
		return nfs3ErrCrossDevice
	case errors.Is(err, syscall.EMLINK):
		return nfs3ErrTooManyLinks
	case errors.Is(err, syscall.ENOTDIR):
		return nfs3ErrNotDir
	case errors.Is(err, syscall.EISDIR):
		return nfs3ErrIsDir
	case errors.Is(err, syscall.EINVAL):
		return nfs3ErrInvalid
	case errors.Is(err, syscall.EFBIG):
		return nfs3ErrFileTooBig
	case errors.Is(err, syscall.ENOSPC):
		return nfs3ErrNoSpace
	case errors.Is(err, syscall.EROFS):
		return nfs3ErrReadOnly
	case errors.Is(err, syscall.ESTALE):
		return nfs3ErrStale
	case errors.Is(err, syscall.ENAMETOOLONG):
		return nfs3ErrNameTooLong
	default:
		return nfs3ErrIO
	}
}

func (server *nfsServer) lookup(files nfsFiles, directory string, parent fs.FileInfo, name string) []byte {
	if parent == nil || !parent.IsDir() {
		return nfsReplyError(3, nfs3ErrNotDir)
	}
	if name == "" {
		return nfsReplyError(3, nfs3ErrNoEnt)
	}
	if (!fs.ValidPath(name) && name != "..") || strings.ContainsAny(name, "/\\\x00") {
		return nfsReplyError(3, nfs3ErrInvalid)
	}
	target := path.Join(directory, name)
	if target == ".." {
		target = "."
	}
	child, err := files.stat(target)
	if err != nil {
		return nfsReplyError(3, nfsFileError(err))
	}
	handle := server.issueHandle(target, child)
	if handle == nil {
		return nfsReplyError(3, nfs3ErrIO)
	}
	wire := nfsPostAttr(nfsOpaque(nfsWords(0), handle), child)
	return nfsPostAttr(wire, parent)
}

func (files nfsFiles) read(name string, info fs.FileInfo, statErr error, args []byte) []byte {
	if statErr != nil {
		return nfsReplyError(6, nfsFileError(statErr))
	}
	offset := binary.BigEndian.Uint64(args)
	count := binary.BigEndian.Uint32(args[8:])
	if offset > math.MaxInt64 || !info.Mode().IsRegular() {
		return nfsReplyError(6, nfs3ErrIO)
	}
	file, err := files.open(name, os.O_RDONLY)
	if err != nil {
		return nfsReplyError(6, nfsFileError(err))
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nfsReplyError(6, nfs3ErrIO)
	}
	data := make([]byte, min(count, files.transfer))
	n, err := file.ReadAt(data, int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return nfsReplyError(6, nfsFileError(err))
	}
	if after, statErr := file.Stat(); statErr == nil {
		opened = after
	}
	eof := uint32(0)
	if errors.Is(err, io.EOF) || offset+uint64(n) >= uint64(opened.Size()) {
		eof = 1
	}
	reply := nfsPostAttr(nfsWords(0), opened)
	reply = append(reply, nfsWords(uint32(n), eof)...)
	return nfsOpaque(reply, data[:n])
}

func (server *nfsServer) readDir(procedure uint32, files nfsFiles, name string, handle []byte, info fs.FileInfo, args, reply []byte) []byte {
	plus := procedure == 17
	if info == nil || !info.IsDir() {
		return nfsReplyError(procedure, nfs3ErrNotDir)
	}
	dir, err := files.openDir(name)
	if err != nil {
		return nfsReplyError(procedure, nfsFileError(err))
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nfsReplyError(procedure, nfs3ErrStale)
	}
	entries, err := fs.ReadDir(dir.FS(), ".")
	if err != nil {
		return nfsReplyError(procedure, nfsFileError(err))
	}

	verifier := nfsDirectoryVerifier(handle, opened, entries)
	cookie := binary.BigEndian.Uint64(args)
	if cookie != 0 && (cookie > uint64(len(entries)) || binary.BigEndian.Uint64(args[8:]) != verifier) {
		return nfsReplyError(procedure, nfs3ErrBadCookie)
	}
	dirCount := binary.BigEndian.Uint32(args[16:])
	maxCount := dirCount
	if plus {
		maxCount = binary.BigEndian.Uint32(args[20:])
	}
	// The status word is outside resok. Reserve the list terminator and EOF.
	limit := int(min(maxCount, files.transfer-1024)) + 4
	const trailer = 8
	reply = binary.BigEndian.AppendUint64(reply, verifier)
	if len(reply)+trailer > limit {
		return nfsReplyError(procedure, nfs3ErrTooSmall)
	}

	index := int(cookie)
	dirBytes := 4 // The directory list's null pointer.
	for index < len(entries) {
		entryName := entries[index].Name()
		child, _ := dir.Lstat(entryName)
		_, fileID := nfsFileIdentity(child)
		entry := binary.BigEndian.AppendUint64(nfsWords(1), fileID)
		entry = nfsOpaque(entry, []byte(entryName))
		entry = binary.BigEndian.AppendUint64(entry, uint64(index+1))
		directoryBytes := len(entry)
		remaining := limit - len(reply) - trailer
		if plus {
			if uint32(dirBytes+directoryBytes) > dirCount || directoryBytes+8 > remaining {
				break
			}
			entry = server.nfsPlusEntry(entry, remaining, path.Join(name, entryName), child)
		} else if directoryBytes > remaining {
			break
		}
		reply = append(reply, entry...)
		dirBytes += directoryBytes
		index++
	}
	if index == int(cookie) && index < len(entries) {
		return nfsReplyError(procedure, nfs3ErrTooSmall)
	}
	eof := uint32(0)
	if index == len(entries) {
		eof = 1
	}
	return append(reply, nfsWords(0, eof)...)
}

func nfsDirectoryVerifier(handle []byte, info fs.FileInfo, entries []fs.DirEntry) uint64 {
	hash := sha256.New()
	hash.Write(handle)
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(info.ModTime().UnixNano())))
	for _, entry := range entries {
		name := entry.Name()
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(name))))
		hash.Write([]byte(name))
	}
	return binary.BigEndian.Uint64(hash.Sum(nil))
}

func (server *nfsServer) nfsPlusEntry(entry []byte, limit int, name string, info fs.FileInfo) []byte {
	const absentHandle = 4
	const presentHandle = 24
	withAttributes := nfsPostAttr(entry, info)
	if len(withAttributes)+absentHandle > limit {
		return append(entry, nfsWords(0, 0)...)
	}
	if info != nil && len(withAttributes)+presentHandle <= limit {
		if handle := server.issueHandle(name, info); handle != nil {
			return nfsOpaque(binary.BigEndian.AppendUint32(withAttributes, 1), handle)
		}
	}
	return binary.BigEndian.AppendUint32(withAttributes, 0)
}

func nfsPostAttr(wire []byte, info fs.FileInfo) []byte {
	if info == nil {
		return binary.BigEndian.AppendUint32(wire, 0)
	}
	return nfsAttr(binary.BigEndian.AppendUint32(wire, 1), info)
}

func nfsAttr(wire []byte, info fs.FileInfo) []byte {
	kind := uint32(1)
	mode := info.Mode()
	switch {
	case mode.IsDir():
		kind = 2
	case mode&fs.ModeSymlink != 0:
		kind = 5
	case mode&fs.ModeNamedPipe != 0:
		kind = 7
	case mode&fs.ModeSocket != 0:
		kind = 6
	case mode&fs.ModeCharDevice != 0:
		kind = 4
	case mode&fs.ModeDevice != 0:
		kind = 3
	}
	permissions := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		permissions |= 04000
	}
	if mode&fs.ModeSetgid != 0 {
		permissions |= 02000
	}
	if mode&fs.ModeSticky != 0 {
		permissions |= 01000
	}
	links, uid, gid := nfsFileOwner(info)
	wire = append(wire, nfsWords(kind, permissions, links, uid, gid)...)
	wire = binary.BigEndian.AppendUint64(wire, uint64(info.Size()))
	wire = binary.BigEndian.AppendUint64(wire, uint64(info.Size()))
	wire = append(wire, nfsWords(0, 0)...)
	filesystemID, fileID := nfsFileIdentity(info)
	wire = binary.BigEndian.AppendUint64(wire, filesystemID)
	wire = binary.BigEndian.AppendUint64(wire, fileID)
	accessed, changed := nfsFileTimes(info)
	wire = nfsTime(wire, accessed)
	wire = nfsTime(wire, info.ModTime())
	return nfsTime(wire, changed)
}
