package protocols

import (
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
)

const (
	nfsMountPath  = "/"
	nfsMountLimit = 128
)

func (server *nfsServer) mountReply(procedure uint32, export string, args []byte, peer net.Addr) (uint32, []byte) {
	client := nfsMountClient(peer)
	switch procedure {
	case 0, 2, 4, 5: // NULL, DUMP, UMNTALL and EXPORT take void arguments.
		if len(args) != 0 {
			return 4, nil // GARBAGE_ARGS
		}
		switch procedure {
		case 2:
			var body []byte
			for _, host := range slices.Sorted(maps.Keys(server.mounted)) {
				body = nfsOpaque(append(body, nfsWords(1)...), []byte(host))
				body = nfsOpaque(body, []byte(nfsMountPath))
			}
			return 0, append(body, nfsWords(0)...)
		case 4:
			delete(server.mounted, client)
		case 5:
			root, err := os.OpenRoot(export)
			if err != nil {
				return 0, nfsWords(0)
			}
			root.Close()
			return 0, append(nfsOpaque(nfsWords(1), []byte(nfsMountPath)), nfsWords(0, 0)...)
		}
		return 0, nil
	case 1, 3: // MNT and UMNT
		mountPath, valid := takeNFSOpaque(&args)
		if !valid || len(args) != 0 || len(mountPath) == 0 || len(mountPath) > 1024 {
			return 4, nil // GARBAGE_ARGS
		}
		if procedure == 3 {
			if string(mountPath) == nfsMountPath {
				delete(server.mounted, client)
			}
			return 0, nil
		}
		if string(mountPath) != nfsMountPath {
			return 0, nfsWords(nfs3ErrNoEnt)
		}
		if _, recorded := server.mounted[client]; !recorded && client != "" && len(server.mounted) >= nfsMountLimit {
			return 0, nfsWords(nfs3ErrServerFault)
		}
		root, err := os.OpenRoot(export)
		if err != nil {
			// OpenRoot can report a non-system directory type error.
			if info, statErr := os.Stat(export); statErr == nil && !info.IsDir() {
				return 0, nfsWords(nfs3ErrNotDir)
			}
			return 0, nfsWords(nfsFileError(err))
		}
		defer root.Close()
		info, err := root.Stat(".")
		if err != nil {
			return 0, nfsWords(nfsFileError(err))
		}
		handle := server.issueHandle(".", info)
		if handle == nil {
			return 0, nfsWords(nfs3ErrIO)
		}
		if client != "" {
			if server.mounted == nil {
				server.mounted = make(map[string]struct{})
			}
			server.mounted[client] = struct{}{}
		}
		body := nfsOpaque(nfsWords(0), handle)
		return 0, append(body, nfsWords(2, rpcAuthSys, rpcAuthNone)...)
	default:
		return 3, nil // PROC_UNAVAIL
	}
}

func nfsMountClient(peer net.Addr) string {
	var address netip.Addr
	switch peer := peer.(type) {
	case *net.TCPAddr:
		address = peer.AddrPort().Addr()
	case *net.UDPAddr:
		address = peer.AddrPort().Addr()
	}
	if !address.IsValid() {
		return ""
	}
	return address.Unmap().WithZone("").String()
}
