package network

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type routeKey struct {
	ip   string // exact IPv4/IPv6 or "0.0.0.0" for subnet-wide wildcard
	port uint16
}

// virtualRouter dynamically dispatches incoming gVisor TCP and UDP flows to
// registered protocol listeners using a single tcp.Forwarder and udp.Forwarder.
// This allows simulating entire /24 or /16 virtual subnets with O(1) memory and
// zero upfront socket fan-out while still returning authentic TCP RSTs for
// closed ports.
type virtualRouter struct {
	ipNet *net.IPNet
	tunIP net.IP

	mu           sync.RWMutex
	tcpListeners map[routeKey]*virtualTCPListener
	udpConns     map[routeKey]*virtualUDPPacketConn
	closed       bool

	// Telemetry/observability counters
	tcpAccepted atomic.Uint64
	tcpRejected atomic.Uint64
	udpAccepted atomic.Uint64
	udpRejected atomic.Uint64
}

func newVirtualRouter(ipNet *net.IPNet, tunIP net.IP) *virtualRouter {
	return &virtualRouter{
		ipNet:        ipNet,
		tunIP:        tunIP,
		tcpListeners: make(map[routeKey]*virtualTCPListener),
		udpConns:     make(map[routeKey]*virtualUDPPacketConn),
	}
}

// Attach registers the TCP and UDP forwarders on the gVisor stack.
// Must be called before stack.CreateNIC so no packets race with registration.
func (r *virtualRouter) Attach(s *stack.Stack) {
	// wndSize=0 uses gVisor's default tuned TCP receive window; maxInFlight=65535
	// absorbs heavy concurrent port-scanner SYN bursts without dropping.
	tcpFwd := tcp.NewForwarder(s, 0, 65535, r.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, r.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

func normalizeVirtualIP(ip string) string {
	if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "::" {
		return "0.0.0.0"
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

// isManagedDest returns true if dstIP is a valid virtual host IP inside the
// configured subnet (never hijacking the OS-side TUN host IP or .0 network addr).
func (r *virtualRouter) isManagedDest(dstIP net.IP) bool {
	if r.ipNet == nil || dstIP == nil {
		return false
	}
	if !r.ipNet.Contains(dstIP) {
		return false
	}
	if r.tunIP != nil && dstIP.Equal(r.tunIP) {
		return false
	}
	if ip4 := dstIP.To4(); ip4 != nil {
		ones, bits := r.ipNet.Mask.Size()
		if bits == 32 && ones < 31 && ip4.Equal(r.ipNet.IP.To4()) {
			return false
		}
	}
	return true
}

func (r *virtualRouter) ListenTCP(ip string, port uint16) (net.Listener, error) {
	key := routeKey{ip: normalizeVirtualIP(ip), port: port}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if _, exists := r.tcpListeners[key]; exists {
		return nil, fmt.Errorf("virtual tcp listener %s:%d already registered", key.ip, key.port)
	}
	ln := &virtualTCPListener{
		router: r,
		key:    key,
		addr:   &net.TCPAddr{IP: net.ParseIP(key.ip), Port: int(port)},
		accept: make(chan net.Conn, 1024),
		done:   make(chan struct{}),
	}
	r.tcpListeners[key] = ln
	return ln, nil
}

func (r *virtualRouter) ListenUDP(ip string, port uint16) (net.PacketConn, error) {
	key := routeKey{ip: normalizeVirtualIP(ip), port: port}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if _, exists := r.udpConns[key]; exists {
		return nil, fmt.Errorf("virtual udp listener %s:%d already registered", key.ip, key.port)
	}
	pc := &virtualUDPPacketConn{
		router: r,
		key:    key,
		addr:   &net.UDPAddr{IP: net.ParseIP(key.ip), Port: int(port)},
		rxCh:   make(chan virtualUDPDatagram, 1024),
		peers:  make(map[string]*gonet.UDPConn),
		done:   make(chan struct{}),
	}
	r.udpConns[key] = pc
	return pc, nil
}

func (r *virtualRouter) lookupTCP(dstIP net.IP, port uint16) *virtualTCPListener {
	if !r.isManagedDest(dstIP) {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	if ln, ok := r.tcpListeners[routeKey{ip: dstIP.String(), port: port}]; ok {
		return ln
	}
	if ln, ok := r.tcpListeners[routeKey{ip: "0.0.0.0", port: port}]; ok {
		return ln
	}
	return nil
}

func (r *virtualRouter) lookupUDP(dstIP net.IP, port uint16) *virtualUDPPacketConn {
	if !r.isManagedDest(dstIP) {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	if pc, ok := r.udpConns[routeKey{ip: dstIP.String(), port: port}]; ok {
		return pc
	}
	if pc, ok := r.udpConns[routeKey{ip: "0.0.0.0", port: port}]; ok {
		return pc
	}
	return nil
}

func (r *virtualRouter) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice())
	ln := r.lookupTCP(dstIP, id.LocalPort)
	if ln == nil {
		r.tcpRejected.Add(1)
		// Send authentic TCP RST for closed virtual ports.
		req.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		r.tcpRejected.Add(1)
		req.Complete(true)
		return
	}
	req.Complete(false)

	ep.SocketOptions().SetKeepAlive(true)
	idleOpt := tcpip.KeepaliveIdleOption(60 * time.Second)
	_ = ep.SetSockOpt(&idleOpt)
	intervalOpt := tcpip.KeepaliveIntervalOption(30 * time.Second)
	_ = ep.SetSockOpt(&intervalOpt)

	conn := gonet.NewTCPConn(&wq, ep)
	if !ln.enqueue(conn) {
		r.tcpRejected.Add(1)
		_ = conn.Close()
		return
	}
	r.tcpAccepted.Add(1)
}

func (r *virtualRouter) handleUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice())
	pc := r.lookupUDP(dstIP, id.LocalPort)
	if pc == nil {
		r.udpRejected.Add(1)
		return false
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		r.udpRejected.Add(1)
		return false
	}
	conn := gonet.NewUDPConn(&wq, ep)
	remoteAddr := &virtualUDPPeerAddr{
		UDPAddr: &net.UDPAddr{
			IP:   append(net.IP(nil), id.RemoteAddress.AsSlice()...),
			Port: int(id.RemotePort),
		},
		localIP: dstIP.String(),
	}
	r.udpAccepted.Add(1)
	go pc.pumpFlow(conn, remoteAddr)
	return true
}

func (r *virtualRouter) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	tcpList := make([]*virtualTCPListener, 0, len(r.tcpListeners))
	for _, ln := range r.tcpListeners {
		tcpList = append(tcpList, ln)
	}
	udpList := make([]*virtualUDPPacketConn, 0, len(r.udpConns))
	for _, pc := range r.udpConns {
		udpList = append(udpList, pc)
	}
	r.tcpListeners = make(map[routeKey]*virtualTCPListener)
	r.udpConns = make(map[routeKey]*virtualUDPPacketConn)
	r.mu.Unlock()

	for _, ln := range tcpList {
		ln.closeLocal()
	}
	for _, pc := range udpList {
		pc.closeLocal()
	}
}

// virtualTCPListener implements net.Listener backed by virtualRouter.
type virtualTCPListener struct {
	router *virtualRouter
	key    routeKey
	addr   net.Addr
	accept chan net.Conn
	done   chan struct{}
	once   sync.Once
}

func (l *virtualTCPListener) enqueue(c net.Conn) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.accept <- c:
		return true
	case <-l.done:
		return false
	default:
		return false
	}
}

func (l *virtualTCPListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *virtualTCPListener) closeLocal() {
	l.once.Do(func() {
		close(l.done)
		for {
			select {
			case c := <-l.accept:
				_ = c.Close()
			default:
				return
			}
		}
	})
}

func (l *virtualTCPListener) Close() error {
	l.router.mu.Lock()
	if cur, ok := l.router.tcpListeners[l.key]; ok && cur == l {
		delete(l.router.tcpListeners, l.key)
	}
	l.router.mu.Unlock()
	l.closeLocal()
	return nil
}

func (l *virtualTCPListener) Addr() net.Addr { return l.addr }

type virtualUDPPeerAddr struct {
	*net.UDPAddr
	localIP string
}

func (a *virtualUDPPeerAddr) peerKey() string {
	return a.UDPAddr.String() + "|" + a.localIP
}

type virtualUDPDatagram struct {
	data   []byte
	remote net.Addr
}

// virtualUDPPacketConn implements net.PacketConn backed by virtualRouter's udp.Forwarder.
type virtualUDPPacketConn struct {
	router *virtualRouter
	key    routeKey
	addr   net.Addr
	rxCh   chan virtualUDPDatagram

	peerMu sync.RWMutex
	peers  map[string]*gonet.UDPConn

	done chan struct{}
	once sync.Once
}

func (p *virtualUDPPacketConn) pumpFlow(conn *gonet.UDPConn, remote *virtualUDPPeerAddr) {
	peerKey := remote.peerKey()
	p.peerMu.Lock()
	prev := p.peers[peerKey]
	p.peers[peerKey] = conn
	p.peerMu.Unlock()
	if prev != nil {
		_ = prev.Close()
	}

	defer func() {
		p.peerMu.Lock()
		if cur, ok := p.peers[peerKey]; ok && cur == conn {
			delete(p.peers, peerKey)
		}
		p.peerMu.Unlock()
		_ = conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-p.done:
			return
		default:
		}
		// Keep UDP flow alive briefly for multi-packet protocols (TFTP, SNMP, IKE),
		// then auto-reclaim to prevent goroutine leaks during large UDP scans.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			select {
			case p.rxCh <- virtualUDPDatagram{data: cp, remote: remote}:
			case <-p.done:
				return
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *virtualUDPPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case dg := <-p.rxCh:
		n := copy(b, dg.data)
		return n, dg.remote, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}

func (p *virtualUDPPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("nil remote address")
	}
	var conn *gonet.UDPConn
	p.peerMu.RLock()
	if vp, ok := addr.(*virtualUDPPeerAddr); ok {
		conn = p.peers[vp.peerKey()]
	} else {
		// Fallback for handlers that construct a plain *net.UDPAddr
		prefix := addr.String() + "|"
		for k, c := range p.peers {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				conn = c
				break
			}
		}
	}
	p.peerMu.RUnlock()
	if conn == nil {
		return 0, net.ErrClosed
	}
	return conn.Write(b)
}

func (p *virtualUDPPacketConn) closeLocal() {
	p.once.Do(func() {
		close(p.done)
		p.peerMu.Lock()
		for k, c := range p.peers {
			_ = c.Close()
			delete(p.peers, k)
		}
		p.peerMu.Unlock()
	})
}

func (p *virtualUDPPacketConn) Close() error {
	p.router.mu.Lock()
	if cur, ok := p.router.udpConns[p.key]; ok && cur == p {
		delete(p.router.udpConns, p.key)
	}
	p.router.mu.Unlock()
	p.closeLocal()
	return nil
}

func (p *virtualUDPPacketConn) LocalAddr() net.Addr                { return p.addr }
func (p *virtualUDPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *virtualUDPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *virtualUDPPacketConn) SetWriteDeadline(t time.Time) error { return nil }
