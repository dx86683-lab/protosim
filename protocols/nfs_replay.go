package protocols

import (
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

const (
	nfsReplayTTL   = 30 * time.Second
	nfsReplaySlots = 128
)

type nfsReplayKey struct {
	peer    string
	export  string
	request [sha256.Size]byte
}

type nfsReplayEntry struct {
	key      nfsReplayKey
	wire     []byte
	deadline time.Time
}

type nfsReplayCache struct {
	mu   sync.Mutex
	ring [nfsReplaySlots]nfsReplayEntry
	next int
}

func (cache *nfsReplayCache) reply(peer, export string, call []byte, execute func() []byte) []byte {
	key := nfsReplayKey{peer, export, sha256.Sum256(call)}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := time.Now()
	for _, entry := range cache.ring {
		if now.Before(entry.deadline) && entry.key == key {
			return entry.wire
		}
	}
	wire := execute()
	cache.ring[cache.next] = nfsReplayEntry{key, wire, time.Now().Add(nfsReplayTTL)}
	cache.next = (cache.next + 1) % len(cache.ring)
	return wire
}

func (server *nfsServer) replayMutation(peer net.Addr, export string, call []byte, execute func() []byte) []byte {
	switch peer := peer.(type) {
	case *net.TCPAddr:
		if address := peer.AddrPort().Addr(); address.IsValid() {
			// A reconnected client can have a different source port.
			return server.tcpReplay.reply(address.Unmap().String(), export, call, execute)
		}
	case *net.UDPAddr:
		return server.udpReplay.reply(peer.String(), export, call, execute)
	}
	return execute()
}

func nfsMutationProcedure(procedure uint32) bool {
	switch procedure {
	case 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 21:
		return true
	default:
		return false
	}
}
