package protocols

import (
	"crypto/rand"
	"io/fs"
	"os"
	"strings"
)

const nfsHandleLimit = 4096

type nfsHandle struct {
	name    string
	info    fs.FileInfo
	aliases map[string]struct{}
}

// Handle operations run under nfsServer.mu, including the file operation.
func (server *nfsServer) issueHandle(name string, info fs.FileInfo) []byte {
	if handle, found := server.paths[name]; found {
		entry := server.handles[handle]
		if entry.info == nil || info == nil || os.SameFile(entry.info, info) {
			if entry.info == nil && info != nil {
				entry.info = info
				server.handles[handle] = entry
			}
			return handle[:]
		}
		server.dropHandlePath(name, handle)
	}
	if len(server.paths) >= nfsHandleLimit {
		return nil
	}
	if info != nil && !info.IsDir() {
		links, _, _ := nfsFileOwner(info)
		if links > 1 {
			for handle, entry := range server.handles {
				if entry.info != nil && os.SameFile(entry.info, info) {
					server.addHandleAlias(handle, name)
					return handle[:]
				}
			}
		}
	}
	if server.handles == nil {
		server.handles = make(map[[16]byte]nfsHandle)
		server.paths = make(map[string][16]byte)
	}
	var handle [16]byte
	for {
		rand.Read(handle[:])
		handle[6] = (handle[6] & 0x0f) | 0x40
		handle[8] = (handle[8] & 0x3f) | 0x80
		if _, exists := server.handles[handle]; !exists {
			break
		}
	}
	server.handles[handle] = nfsHandle{name: name, info: info}
	server.paths[name] = handle
	return handle[:]
}

func (server *nfsServer) resolveHandle(wire []byte, files nfsFiles) (string, fs.FileInfo, error) {
	if len(wire) != 16 {
		return "", nil, nil
	}
	handle := [16]byte(wire)
	for entry, ok := server.handles[handle]; ok; entry, ok = server.handles[handle] {
		info, err := files.stat(entry.name)
		if entry.info == nil || (err == nil && os.SameFile(entry.info, info)) {
			return entry.name, info, err
		}
		server.dropHandlePath(entry.name, handle)
	}
	return "", nil, nil
}

func (server *nfsServer) addHandleAlias(handle [16]byte, name string) {
	if _, exists := server.paths[name]; exists || len(server.paths) >= nfsHandleLimit {
		return
	}
	entry := server.handles[handle]
	if entry.aliases == nil {
		entry.aliases = make(map[string]struct{})
	}
	entry.aliases[name] = struct{}{}
	server.paths[name] = handle
	server.handles[handle] = entry
}

func (server *nfsServer) dropHandlePath(name string, handle [16]byte) {
	delete(server.paths, name)
	entry := server.handles[handle]
	if name != entry.name {
		delete(entry.aliases, name)
		return
	}
	if len(entry.aliases) == 0 {
		delete(server.handles, handle)
		return
	}
	for alias := range entry.aliases {
		entry.name = alias
		delete(entry.aliases, alias)
		server.handles[handle] = entry
		break
	}
}

func (server *nfsServer) forgetHandles(name string) {
	for candidate, handle := range server.paths {
		if candidate == name || strings.HasPrefix(candidate, name+"/") {
			server.dropHandlePath(candidate, handle)
		}
	}
}

func (server *nfsServer) moveHandles(source, destination string) {
	if source == destination {
		return
	}
	server.forgetHandles(destination)
	type movedHandle struct {
		oldPath string
		newPath string
		handle  [16]byte
	}
	var moved []movedHandle
	for candidate, handle := range server.paths {
		if candidate != source && !strings.HasPrefix(candidate, source+"/") {
			continue
		}
		moved = append(moved, movedHandle{
			oldPath: candidate,
			newPath: destination + strings.TrimPrefix(candidate, source),
			handle:  handle,
		})
	}
	for _, m := range moved {
		entry := server.handles[m.handle]
		if entry.name == m.oldPath {
			entry.name = m.newPath
		} else {
			delete(entry.aliases, m.oldPath)
			if entry.aliases == nil {
				entry.aliases = make(map[string]struct{})
			}
			entry.aliases[m.newPath] = struct{}{}
		}
		server.handles[m.handle] = entry
		delete(server.paths, m.oldPath)
		server.paths[m.newPath] = m.handle
	}
}
