package protocols

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"math"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

func nfsTime(wire []byte, stamp time.Time) []byte {
	return append(wire, nfsWords(uint32(stamp.Unix()), uint32(stamp.Nanosecond()))...)
}

func nfsWCC(wire []byte, before, after fs.FileInfo) []byte {
	if before == nil {
		wire = binary.BigEndian.AppendUint32(wire, 0)
	} else {
		wire = binary.BigEndian.AppendUint32(wire, 1)
		wire = binary.BigEndian.AppendUint64(wire, uint64(before.Size()))
		wire = nfsTime(wire, before.ModTime())
		_, changed := nfsFileTimes(before)
		wire = nfsTime(wire, changed)
	}
	return nfsPostAttr(wire, after)
}

func (server *nfsServer) write(files nfsFiles, name string, before fs.FileInfo, statErr error, args []byte) []byte {
	const fileSync = 2
	if len(args) < 16 {
		return nfsReplyError(7, nfs3ErrInvalid)
	}
	if statErr != nil {
		return nfsReplyError(7, nfsFileError(statErr))
	}
	offset := binary.BigEndian.Uint64(args)
	count := binary.BigEndian.Uint32(args[8:])
	stable := binary.BigEndian.Uint32(args[12:])
	args = args[16:]
	data, valid := takeNFSOpaque(&args)
	if !valid || len(args) != 0 || count != uint32(len(data)) || stable > fileSync || !before.Mode().IsRegular() {
		return nfsReplyError(7, nfs3ErrInvalid)
	}
	writeCount := min(count, files.transfer)
	if writeCount != 0 && offset > math.MaxInt64-uint64(writeCount) {
		return nfsWCC(nfsWords(nfs3ErrFileTooBig), before, before)
	}
	file, opened, err := files.openWriteFile(name, before)
	if err != nil {
		return nfsWCC(nfsWords(nfsFileError(err)), before, nil)
	}
	defer file.Close()
	n := 0
	if writeCount != 0 {
		n, err = file.WriteAt(data[:writeCount], int64(offset))
	}
	if err == nil {
		err = file.Sync()
	}
	after, _ := file.Stat()
	if err != nil {
		return nfsWCC(nfsWords(nfsFileError(err)), opened, after)
	}
	reply := nfsWCC(nfsWords(0), opened, after)
	reply = append(reply, nfsWords(uint32(n), fileSync)...)
	return append(reply, server.verifier[:]...)
}

func (server *nfsServer) commit(files nfsFiles, name string, before fs.FileInfo, statErr error, args []byte) []byte {
	if len(args) != 12 || binary.BigEndian.Uint64(args) > math.MaxInt64 {
		return nfsReplyError(21, nfs3ErrInvalid)
	}
	if statErr != nil {
		return nfsReplyError(21, nfsFileError(statErr))
	}
	if !before.Mode().IsRegular() {
		return nfsWCC(nfsWords(nfs3ErrInvalid), before, before)
	}
	file, opened, err := files.openWriteFile(name, before)
	if err != nil {
		return nfsWCC(nfsWords(nfsFileError(err)), before, nil)
	}
	defer file.Close()

	// A whole-file sync also covers a requested byte range and its metadata.
	err = file.Sync()
	after, _ := file.Stat()
	if err != nil {
		return nfsWCC(nfsWords(nfsFileError(err)), opened, after)
	}
	return append(nfsWCC(nfsWords(0), opened, after), server.verifier[:]...)
}

func (files nfsFiles) openWriteFile(name string, expected fs.FileInfo) (*os.File, fs.FileInfo, error) {
	file, err := files.openAttributes(name, os.O_WRONLY)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		file.Close()
		return nil, nil, syscall.ESTALE
	}
	return file, info, nil
}

func nfsTakeWord(args *[]byte) (uint32, bool) {
	if len(*args) < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(*args)
	*args = (*args)[4:]
	return value, true
}

type nfsSetAttributes struct {
	mode     fs.FileMode
	size     uint64
	setMode  bool
	setSize  bool
	setOwner bool
	times    [2]nfsSetTime
}

const (
	nfsTimeUnchanged = iota
	nfsTimeServer
	nfsTimeClient
)

type nfsSetTime struct {
	how         uint32
	seconds     uint32
	nanoseconds uint32
}

func (attr nfsSetAttributes) changesTimes() bool {
	return attr.times[0].how != nfsTimeUnchanged || attr.times[1].how != nfsTimeUnchanged
}

func takeNFSSetAttributes(args *[]byte) (nfsSetAttributes, bool) {
	var attr nfsSetAttributes
	for field, width := range [...]int{4, 4, 4, 8} {
		set, valid := nfsTakeWord(args)
		if !valid || set > 1 {
			return attr, false
		}
		if set == 0 {
			continue
		}
		if len(*args) < width {
			return attr, false
		}
		switch field {
		case 0:
			attr.mode = fs.FileMode(binary.BigEndian.Uint32(*args))
			attr.setMode = true
		case 3:
			attr.size = binary.BigEndian.Uint64(*args)
			attr.setSize = true
		default:
			attr.setOwner = true
		}
		*args = (*args)[width:]
	}
	for i := range attr.times {
		how, valid := nfsTakeWord(args)
		if !valid || how > nfsTimeClient {
			return attr, false
		}
		attr.times[i].how = how
		if how == nfsTimeClient {
			if len(*args) < 8 {
				return attr, false
			}
			attr.times[i].seconds = binary.BigEndian.Uint32(*args)
			attr.times[i].nanoseconds = binary.BigEndian.Uint32((*args)[4:])
			if attr.times[i].nanoseconds >= 1_000_000_000 {
				return attr, false
			}
			*args = (*args)[8:]
		}
	}
	return attr, true
}

func (files nfsFiles) setAttr(name string, before fs.FileInfo, statErr error, args []byte) []byte {
	attr, valid := takeNFSSetAttributes(&args)
	guard, hasGuard := nfsTakeWord(&args)
	if !valid || !hasGuard || guard > 1 || (guard == 1 && (len(args) != 8 || binary.BigEndian.Uint32(args[4:]) >= 1_000_000_000)) {
		return nfsReplyError(2, nfs3ErrInvalid)
	}
	if statErr != nil {
		return nfsReplyError(2, nfsFileError(statErr))
	}
	if attr.setOwner || attr.mode != attr.mode.Perm() {
		return nfsWCC(nfsWords(nfs3ErrPerm), before, before)
	}
	if attr.changesTimes() && !nfsSupportsTimeUpdates {
		return nfsWCC(nfsWords(nfs3ErrNotSupp), before, before)
	}
	if attr.size > math.MaxInt64 || (attr.setSize && !before.Mode().IsRegular()) ||
		(attr.setMode && !before.Mode().IsRegular() && !before.IsDir()) {
		return nfsReplyError(2, nfs3ErrInvalid)
	}
	if !attr.setSize && !attr.setMode && !attr.changesTimes() {
		return nfsWCC(nfsWords(nfsAttrGuard(guard, args, before)), before, before)
	}
	var file *os.File
	var err error
	switch {
	case attr.setSize:
		file, err = files.openAttributes(name, os.O_WRONLY)
	case attr.setMode:
		file, err = files.openAttributes(name, os.O_RDONLY)
	default:
		file, err = files.openTimeTarget(name)
	}
	if err != nil {
		return nfsReplyError(2, nfsFileError(err))
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nfsReplyError(2, nfs3ErrIO)
	}
	if status := nfsAttrGuard(guard, args, opened); status != 0 {
		return nfsWCC(nfsWords(status), opened, opened)
	}
	status := uint32(0)
	if err := attr.apply(file); err != nil {
		status = nfsFileError(err)
	}
	after, _ := file.Stat()
	return nfsWCC(nfsWords(status), opened, after)
}

func nfsAttrGuard(guard uint32, args []byte, info fs.FileInfo) uint32 {
	_, changed := nfsFileTimes(info)
	if guard == 1 && (uint32(changed.Unix()) != binary.BigEndian.Uint32(args) ||
		uint32(changed.Nanosecond()) != binary.BigEndian.Uint32(args[4:])) {
		return nfs3ErrNotSync
	}
	return 0
}

func (attr nfsSetAttributes) apply(file *os.File) error {
	if attr.setSize {
		if err := file.Truncate(int64(attr.size)); err != nil {
			return err
		}
	}
	if attr.setMode {
		if err := file.Chmod(attr.mode); err != nil {
			return err
		}
	}
	if attr.changesTimes() {
		return nfsSetFileTimes(file, attr.times)
	}
	return nil
}

func takeNFSChild(parent string, args *[]byte) (string, bool) {
	value, valid := takeNFSOpaque(args)
	name := string(value)
	if !valid || name == "." || !fs.ValidPath(name) || strings.ContainsAny(name, "/\\\x00") {
		return "", false
	}
	return path.Join(parent, name), true
}

func (server *nfsServer) create(procedure uint32, files nfsFiles, directory string, parent fs.FileInfo, args []byte) []byte {
	if parent == nil {
		return nfsReplyError(procedure, nfs3ErrAccess)
	}
	if !parent.IsDir() {
		return nfsReplyError(procedure, nfs3ErrNotDir)
	}
	child, valid := takeNFSChild(directory, &args)
	if !valid {
		return nfsReplyError(procedure, nfs3ErrInvalid)
	}
	switch procedure {
	case 8: // CREATE
		return server.createFile(files, directory, child, parent, args)
	case 9: // MKDIR
		return server.mkdir(files, directory, child, parent, args)
	case 10: // SYMLINK
		return server.symlink(files, directory, child, parent, args)
	default:
		return nfsReplyError(procedure, nfs3ErrNotSupp)
	}
}

func (server *nfsServer) symlink(files nfsFiles, directory, child string, parent fs.FileInfo, args []byte) []byte {
	attr, valid := takeNFSSetAttributes(&args)
	wire, hasTarget := takeNFSOpaque(&args)
	target := string(wire)
	if !valid || !hasTarget || len(args) != 0 || target == "" || strings.ContainsRune(target, 0) || attr.setSize {
		return nfsWCC(nfsWords(nfs3ErrInvalid), parent, parent)
	}
	if attr.setOwner || attr.mode != attr.mode.Perm() {
		return nfsWCC(nfsWords(nfs3ErrPerm), parent, parent)
	}
	if attr.changesTimes() && !nfsSupportsTimeUpdates {
		return nfsWCC(nfsWords(nfs3ErrNotSupp), parent, parent)
	}
	// The client interprets the target. The export root confines later file operations.
	if err := files.root.Symlink(target, child); err != nil {
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	info, err := files.stat(child)
	if err == nil && attr.changesTimes() {
		info, err = files.applySymlinkTimes(child, info, attr.times)
	}
	if err != nil {
		if current, statErr := files.stat(child); info != nil && statErr == nil && os.SameFile(info, current) {
			_ = files.removeEntry(directory, path.Base(child), parent, false)
		}
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	return server.createReply(files, directory, child, parent, info)
}

func (files nfsFiles) applySymlinkTimes(name string, info fs.FileInfo, times [2]nfsSetTime) (fs.FileInfo, error) {
	file, err := files.openTimeTarget(name)
	if err != nil {
		return info, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return info, err
	}
	if opened.Mode()&fs.ModeSymlink == 0 || !os.SameFile(opened, info) {
		return info, syscall.ESTALE
	}
	if err := nfsSetFileTimes(file, times); err != nil {
		return opened, err
	}
	after, _ := file.Stat()
	return after, nil
}

func (server *nfsServer) mkdir(files nfsFiles, directory, child string, parent fs.FileInfo, args []byte) []byte {
	attr, valid := takeNFSSetAttributes(&args)
	if !valid || len(args) != 0 || attr.setSize {
		return nfsWCC(nfsWords(nfs3ErrInvalid), parent, parent)
	}
	if attr.setOwner || attr.mode != attr.mode.Perm() {
		return nfsWCC(nfsWords(nfs3ErrPerm), parent, parent)
	}
	if attr.changesTimes() && !nfsSupportsTimeUpdates {
		return nfsWCC(nfsWords(nfs3ErrNotSupp), parent, parent)
	}
	mode := fs.FileMode(0755)
	if attr.setMode {
		mode = 0700 // Owner access while applying the requested attributes.
	}
	if err := files.root.Mkdir(child, mode); err != nil {
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	info, err := files.stat(child)
	if err == nil && (attr.setMode || attr.changesTimes()) {
		info, err = files.applyDirectoryAttributes(child, info, attr)
	}
	if err != nil {
		if current, statErr := files.stat(child); info != nil && statErr == nil && os.SameFile(info, current) {
			_ = files.removeEntry(directory, path.Base(child), parent, true)
		}
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	return server.createReply(files, directory, child, parent, info)
}

func (files nfsFiles) applyDirectoryAttributes(child string, info fs.FileInfo, attr nfsSetAttributes) (fs.FileInfo, error) {
	file, err := files.openAttributes(child, os.O_RDONLY)
	if err != nil {
		return info, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return info, err
	}
	if !opened.IsDir() || !os.SameFile(info, opened) {
		return info, fs.ErrNotExist
	}
	if err := attr.apply(file); err != nil {
		return opened, err
	}
	after, _ := file.Stat()
	return after, nil
}

func (server *nfsServer) createFile(files nfsFiles, directory, child string, parent fs.FileInfo, args []byte) []byte {
	mode, valid := nfsTakeWord(&args)
	if !valid || mode > 2 {
		return nfsReplyError(8, nfs3ErrInvalid)
	}
	if mode == 2 {
		if len(args) != 8 {
			return nfsReplyError(8, nfs3ErrInvalid)
		}
		info, err := files.createExclusive(directory, path.Base(child), parent, args)
		if err == nil {
			return server.createReply(files, directory, child, parent, info)
		}
		status := nfsFileError(err)
		if errors.Is(err, errors.ErrUnsupported) {
			status = nfs3ErrNotSupp
		}
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(status), parent, after)
	}
	attr, valid := takeNFSSetAttributes(&args)
	if !valid || attr.size > math.MaxInt64 {
		return nfsReplyError(8, nfs3ErrInvalid)
	}
	if attr.setOwner || attr.mode != attr.mode.Perm() {
		return nfsWCC(nfsWords(nfs3ErrPerm), parent, parent)
	}
	if attr.changesTimes() && !nfsSupportsTimeUpdates {
		return nfsWCC(nfsWords(nfs3ErrNotSupp), parent, parent)
	}
	file, err := files.root.OpenFile(child, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	newFile := err == nil
	if mode == 0 && errors.Is(err, fs.ErrExist) {
		existing, statErr := files.stat(child)
		if statErr != nil {
			return nfsWCC(nfsWords(nfsFileError(statErr)), parent, parent)
		}
		if !existing.Mode().IsRegular() {
			return nfsWCC(nfsWords(nfs3ErrExist), parent, parent)
		}
		if !attr.setSize {
			return server.createReply(files, directory, child, parent, existing)
		}
		attr.setMode = false
		attr.times = [2]nfsSetTime{}
		file, err = files.openAttributes(child, os.O_WRONLY)
		if err == nil {
			opened, statErr := file.Stat()
			if statErr != nil || !os.SameFile(existing, opened) {
				file.Close()
				return nfsReplyError(8, nfs3ErrStale)
			}
		}
	}
	if err != nil {
		return nfsWCC(nfsWords(nfsFileError(err)), parent, parent)
	}
	defer file.Close()
	if err := attr.apply(file); err != nil {
		if newFile {
			opened, openErr := file.Stat()
			current, statErr := files.stat(child)
			if openErr == nil && statErr == nil && os.SameFile(opened, current) {
				_ = files.root.Remove(child)
			}
		}
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	info, _ := file.Stat()
	return server.createReply(files, directory, child, parent, info)
}

func (server *nfsServer) createReply(files nfsFiles, directory, name string, parent, child fs.FileInfo) []byte {
	after, _ := files.stat(directory)
	reply := nfsWords(0)
	if handle := server.issueHandle(name, child); handle != nil {
		reply = nfsOpaque(binary.BigEndian.AppendUint32(reply, 1), handle)
	} else {
		reply = binary.BigEndian.AppendUint32(reply, 0)
	}
	return nfsWCC(nfsPostAttr(reply, child), parent, after)
}

func (server *nfsServer) remove(procedure uint32, files nfsFiles, directory string, parent fs.FileInfo, statErr error, args []byte) []byte {
	if statErr != nil {
		return nfsReplyError(procedure, nfsFileError(statErr))
	}
	if !parent.IsDir() {
		return nfsReplyError(procedure, nfs3ErrNotDir)
	}
	child, valid := takeNFSChild(directory, &args)
	if !valid {
		return nfsReplyError(procedure, nfs3ErrInvalid)
	}
	if err := files.removeEntry(directory, path.Base(child), parent, procedure == 13); err != nil {
		after, _ := files.stat(directory)
		return nfsWCC(nfsWords(nfsFileError(err)), parent, after)
	}
	server.forgetHandles(child)
	after, _ := files.stat(directory)
	return nfsWCC(nfsWords(0), parent, after)
}

func (server *nfsServer) rename(files nfsFiles, directory string, parent fs.FileInfo, statErr error, args []byte) []byte {
	if statErr != nil {
		return nfsReplyError(14, nfsFileError(statErr))
	}
	if !parent.IsDir() {
		return nfsReplyError(14, nfs3ErrNotDir)
	}
	sourceError := func(status uint32) []byte {
		return nfsWCC(nfsWCC(nfsWords(status), parent, parent), nil, nil)
	}
	source, sourceOK := takeNFSChild(directory, &args)
	destinationHandle, handleOK := takeNFSOpaque(&args)
	if !sourceOK || !handleOK {
		return sourceError(nfs3ErrInvalid)
	}
	destinationDirectory, destinationParent, destinationErr := server.resolveHandle(destinationHandle, files)
	if destinationDirectory == "" {
		return sourceError(nfs3ErrStale)
	}
	if destinationErr != nil {
		return sourceError(nfsFileError(destinationErr))
	}
	if !destinationParent.IsDir() {
		return sourceError(nfs3ErrNotDir)
	}
	destination, destinationOK := takeNFSChild(destinationDirectory, &args)
	if !destinationOK || len(args) != 0 {
		return nfsWCC(nfsWCC(nfsWords(nfs3ErrInvalid), parent, parent), destinationParent, destinationParent)
	}
	after, destinationAfter, err := files.renameEntry(source, destination, parent, destinationParent)
	status := uint32(0)
	if err != nil {
		status = nfsFileError(err)
		switch status {
		case nfs3ErrNotEmpty, nfs3ErrNotDir, nfs3ErrIsDir:
			status = nfs3ErrExist
		}
	} else {
		sourceInfo, sourceErr := files.stat(source)
		targetInfo, targetErr := files.stat(destination)
		if sourceErr != nil || targetErr != nil || !os.SameFile(sourceInfo, targetInfo) {
			server.moveHandles(source, destination)
		}
	}
	return nfsWCC(nfsWCC(nfsWords(status), parent, after), destinationParent, destinationAfter)
}

func (server *nfsServer) link(files nfsFiles, name string, info fs.FileInfo, statErr error, args []byte) []byte {
	if statErr != nil {
		return nfsReplyError(15, nfs3ErrStale)
	}
	handle, valid := takeNFSOpaque(&args)
	if !valid {
		return nfsReplyError(15, nfs3ErrInvalid)
	}
	directory, parent, statErr := server.resolveHandle(handle, files)
	if directory == "" || statErr != nil {
		return nfsReplyError(15, nfs3ErrStale)
	}
	child, valid := takeNFSChild(directory, &args)
	if !valid || len(args) != 0 {
		return nfsReplyError(15, nfs3ErrInvalid)
	}
	status := uint32(0)
	switch {
	case !parent.IsDir():
		status = nfs3ErrNotDir
	case info.IsDir():
		status = nfs3ErrPerm
	default:
		updated, err := files.hardLink(name, directory, child, info, parent)
		switch {
		case errors.Is(err, errors.ErrUnsupported):
			status = nfs3ErrNotSupp
		case err != nil:
			status = nfsFileError(err)
		default:
			info = updated
			if stale, ok := server.paths[child]; ok {
				server.dropHandlePath(child, stale)
			}
			server.addHandleAlias(server.paths[name], child)
		}
	}
	after, _ := files.stat(directory)
	return nfsWCC(nfsPostAttr(nfsWords(status), info), parent, after)
}
