package protocols

import (
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("mdns", MDNS, 5353))
}

// MDNS implements RFC 6762 Multicast DNS service discovery responses (UDP 5353).
func MDNS(uc *UDPConnection, b []byte) error {
	req := new(dns.Msg)
	if err := req.Unpack(b); err != nil {
		return err
	}

	qnames := make([]string, 0, len(req.Question))
	for _, q := range req.Question {
		qnames = append(qnames, q.Name)
	}
	uc.LogWithRemote("mdns_query", uc.RemoteAddr(), logrus.Fields{
		"questions": qnames,
	})

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypePTR, dns.TypeANY:
			resp.Answer = append(resp.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
				Ptr: "_http._tcp.local.",
			})
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.IPv4(192, 168, 1, 100),
			})
		case dns.TypeTXT:
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
				Txt: []string{"model=ProtoSim", "vers=1.0"},
			})
		}
	}

	raw, err := resp.Pack()
	if err != nil {
		return err
	}
	_, err = uc.WriteTo(raw, uc.RemoteAddr())
	return err
}
