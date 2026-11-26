package protocols

import (
	"errors"
	"io"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestLDAPTerminalOperationsWithQueuedSearch(t *testing.T) {
	search := berTLV(0x30, berIntBytes(2, 4),
		berTLV(0x63, berTLV(4), berIntBytes(0x0a, 0), berIntBytes(0x0a, 0), berIntBytes(2, 0), berIntBytes(2, 0),
			berTLV(1, []byte{0}), berTLV(0x87, []byte("objectClass")), berTLV(0x30)))
	for _, tc := range []struct {
		name string
		op   []byte
	}{
		{"abandon", berIntBytes(0x50, 2)},
		{"unbind", berTLV(0x42)},
	} {
		for _, queued := range []bool{false, true} {
			name := tc.name
			if queued {
				name += "-with-search"
			}
			t.Run(name, func(t *testing.T) {
				conn, stop := startRound6Server(t, round6Case{Handler: "ldap"})
				defer stop()
				if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				request := berTLV(0x30, berIntBytes(2, 3), tc.op)
				if queued {
					request = append(request, search...)
				}
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				var reply [1]byte
				n, err := conn.Read(reply[:])
				const wsaConnReset = syscall.Errno(10054)
				reset := errors.Is(err, syscall.ECONNRESET) || runtime.GOOS == "windows" && errors.Is(err, wsaConnReset)
				if n != 0 || queued && !reset || !queued && !errors.Is(err, io.EOF) {
					t.Fatalf("received %x (%v), want reset=%t without a reply", reply[:n], err, queued)
				}
			})
		}
	}
}

func TestLDAPRefusesSASLAndAllowsAnonymousRebind(t *testing.T) {
	const saslBind = "\x30\x16\x02\x01\x01\x60\x11\x02\x01\x03\x04\x00\xa3\x0a\x04\x08EXTERNAL"
	const refused = "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x30\x04\x00\x04\x00"
	const anonymousBind = "\x30\x0c\x02\x01\x02\x60\x07\x02\x01\x03\x04\x00\x80\x00"
	const accepted = "\x30\x0c\x02\x01\x02\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
	requireReferenceTCP(t, "ldap", nil, []referenceExchange{
		{saslBind, refused},
		{anonymousBind, accepted},
	})
}

func TestLDAPCompareKeepsSessionOpen(t *testing.T) {
	const compare = "\x30\x24\x02\x01\x01\x6e\x1f\x04\x00\x30\x1b\x04\x0b" +
		"dnsHostName\x04\x0cserver.local"
	const refusal = "\x30\x26\x02\x01\x01\x6f\x21\x0a\x01\x32\x04\x00\x04\x1a" +
		"Insufficient Access Rights"
	const bind = "\x30\x0c\x02\x01\x02\x60\x07\x02\x01\x03\x04\x00\x80\x00"
	const accepted = "\x30\x0c\x02\x01\x02\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
	requireReferenceTCP(t, "ldap", nil, []referenceExchange{
		{compare, refusal},
		{bind, accepted},
	})
}

func TestLDAPConfiguredAttributeSpelling(t *testing.T) {
	params := map[string]any{"attrs": map[string]any{
		"dnshostname": []any{"fixture.local"},
		"NewField":    []any{"fixture"},
	}}
	id := berIntBytes(2, 1)
	selected := berTLV(0x30, berTLV(4, []byte("dnshostname")), berTLV(4, []byte("dnsHostName")), berTLV(4, []byte("NewField")))
	request := berTLV(0x30, id, berTLV(0x63, berTLV(4), berIntBytes(0x0a, 0), berIntBytes(0x0a, 0),
		berIntBytes(2, 0), berIntBytes(2, 0), berTLV(1, []byte{0}), berTLV(0x87, []byte("objectClass")), selected,
	))
	dns := berTLV(0x30, berTLV(4, []byte("dnshostname")), berTLV(0x31, berTLV(4, []byte("fixture.local"))))
	custom := berTLV(0x30, berTLV(4, []byte("NewField")), berTLV(0x31, berTLV(4, []byte("fixture"))))
	entry := berTLV(0x30, id, berTLV(0x64, berTLV(4), berTLV(0x30, dns, custom)))
	response := append(entry, ldapResult(1, 0x65, 0, "")...)
	requireReferenceTCP(t, "ldap", params, []referenceExchange{{string(request), string(response)}})
}
