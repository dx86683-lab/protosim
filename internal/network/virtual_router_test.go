package network

import (
	"net"
	"testing"
)

func TestVirtualRouterLookupAndSubnetBounds(t *testing.T) {
	parsedIP, ipNet, err := net.ParseCIDR("10.200.0.1/16")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	r := newVirtualRouter(ipNet, resolveTunHostIP(parsedIP, ipNet))
	defer r.Close()

	lnExact, err := r.ListenTCP("10.200.1.10", 80)
	if err != nil {
		t.Fatalf("ListenTCP exact: %v", err)
	}
	defer lnExact.Close()

	lnWildcard, err := r.ListenTCP("0.0.0.0", 80)
	if err != nil {
		t.Fatalf("ListenTCP wildcard: %v", err)
	}
	defer lnWildcard.Close()

	// Exact IP beats wildcard
	if got := r.lookupTCP(net.ParseIP("10.200.1.10"), 80); got != lnExact {
		t.Fatalf("expected exact listener for 10.200.1.10:80")
	}
	// Arbitrary IP in /16 falls back to wildcard
	if got := r.lookupTCP(net.ParseIP("10.200.250.99"), 80); got != lnWildcard {
		t.Fatalf("expected wildcard listener for 10.200.250.99:80")
	}
	// Closed port returns nil (will trigger TCP RST)
	if got := r.lookupTCP(net.ParseIP("10.200.250.99"), 81); got != nil {
		t.Fatalf("expected nil for closed port 81")
	}
	// Must NOT hijack TUN host IP, .0 network address, or outside-subnet IP
	for _, blocked := range []string{"10.200.0.1", "10.200.0.0", "192.168.124.15"} {
		if got := r.lookupTCP(net.ParseIP(blocked), 80); got != nil {
			t.Fatalf("expected nil for non-managed dest %s, got %v", blocked, got)
		}
	}

	// UDP wildcard & exact
	pcExact, err := r.ListenUDP("10.200.2.20", 69)
	if err != nil {
		t.Fatalf("ListenUDP exact: %v", err)
	}
	defer pcExact.Close()

	pcWild, err := r.ListenUDP("0.0.0.0", 69)
	if err != nil {
		t.Fatalf("ListenUDP wildcard: %v", err)
	}
	defer pcWild.Close()

	if got := r.lookupUDP(net.ParseIP("10.200.2.20"), 69); got != pcExact {
		t.Fatalf("expected exact UDP listener")
	}
	if got := r.lookupUDP(net.ParseIP("10.200.99.99"), 69); got != pcWild {
		t.Fatalf("expected wildcard UDP listener")
	}
	if got := r.lookupUDP(net.ParseIP("10.200.99.99"), 70); got != nil {
		t.Fatalf("expected nil for closed UDP port 70")
	}
}
