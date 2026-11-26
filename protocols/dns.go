package protocols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSDatagramSize allocates room for a complete UDP DNS message from the listener.
const DNSDatagramSize = dns.MaxMsgSize

const (
	dnsHeaderSize   = 12
	dnsResponseFlag = 0x8000
	dnsOpcodeMask   = 0x7800
	dnsQueryFlags   = 0x0110 // RD and CD
	dnsEventWindow  = 1024
	dnsTCPTimeout   = 2 * time.Minute
	dnsEDNSSize     = 4096
)

func init() {
	info := NewProtocolInfo("dns", serveDNSTCP, 53)
	info.DatagramHandler = func(*BindInfo) UDPFunction { return serveDNS }
	AddProtocol(info,
		ProtocolParams{Name: "appname", DefaultValue: "domain"})
}

func serveDNS(conn *UDPConnection, payload []byte) error {
	return serveDNSMessage(conn.ConfigInfo, conn.RemoteAddr(), payload, true, func(wire []byte) error {
		return writeDNSMessage(conn, wire)
	})
}

func serveDNSTCP(session *SessionConnection) error {
	defer session.DeleteActivity()
	conn := session.Conn
	write := func(wire []byte) error {
		if err := conn.SetWriteDeadline(time.Now().Add(dnsTCPTimeout)); err != nil {
			return err
		}
		frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(wire)), uint16(len(wire)))
		return writeDNSMessage(conn, append(frame, wire...))
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(dnsTCPTimeout)); err != nil {
			return err
		}
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return dnsTCPReadError(err)
		}
		size := binary.BigEndian.Uint16(prefix[:])
		if size < dnsHeaderSize {
			return nil
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return dnsTCPReadError(err)
		}
		if err := serveDNSMessage(session.ConfigInfo, conn.RemoteAddr(), payload, false, write); err != nil {
			return err
		}
	}
}

func dnsTCPReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return nil
	}
	return err
}

func writeDNSMessage(conn io.Writer, wire []byte) error {
	n, err := conn.Write(wire)
	if err == nil && n != len(wire) {
		return io.ErrShortWrite
	}
	return err
}

func serveDNSMessage(config *ConfigInfo, peer net.Addr, payload []byte, datagram bool, write func([]byte) error) error {
	if len(payload) < dnsHeaderSize || len(payload) > DNSDatagramSize {
		return nil
	}
	header := dns.Header{
		Id:      binary.BigEndian.Uint16(payload[0:2]),
		Bits:    binary.BigEndian.Uint16(payload[2:4]),
		Qdcount: binary.BigEndian.Uint16(payload[4:6]),
		Ancount: binary.BigEndian.Uint16(payload[6:8]),
		Nscount: binary.BigEndian.Uint16(payload[8:10]),
		Arcount: binary.BigEndian.Uint16(payload[10:12]),
	}
	switch dns.DefaultMsgAcceptFunc(header) {
	case dns.MsgIgnore:
		return nil
	case dns.MsgReject:
		return writeDNSError(write, header, dns.RcodeFormatError)
	case dns.MsgRejectNotImplemented:
		return writeDNSError(write, header, dns.RcodeNotImplemented)
	}

	var request dns.Msg
	if err := request.Unpack(payload); err != nil || len(request.Question) != 1 {
		return writeDNSError(write, header, dns.RcodeFormatError)
	}
	question := request.Question[0]
	fields := logrus.Fields{
		"id": request.Id, "op": dns.OpcodeToString[request.Opcode], "question": dnsQuestionText(question),
	}
	if !datagram {
		fields["transport"] = "tcp"
	}
	event := "new request accept"
	if datagram && len(payload) > dnsEventWindow {
		// The reference's request event parses the captured prefix. Keep the
		// full-datagram reply and a distinct event when that prefix is incomplete.
		var prefix dns.Msg
		if err := prefix.Unpack(payload[:dnsEventWindow]); err != nil || len(prefix.Question) != 1 {
			event = "oversized DNS request accepted"
			fields["payload_size"] = len(payload)
		}
	}
	// The reference does not record an ordinary UDP request event when
	// the query contains the TCP Keepalive option.
	if !datagram || event != "new request accept" || !dnsHasTCPKeepalive(request.Extra) {
		logSessionEvent(config, peer, event, fields)
	}

	reply := new(dns.Msg).SetReply(&request)
	if request.Opcode == dns.OpcodeQuery && (question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR) {
		// The simulator serves no authoritative zones.
		reply.Rcode = dns.RcodeNotAuth
		reply.CheckingDisabled = false
	} else {
		reply.Extra = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{""},
		}}
	}
	requestSize := setDNSOptions(&request, reply, datagram)
	if datagram {
		reply.Truncate(min(dnsEDNSSize, max(dns.MinMsgSize, int(requestSize))))
	}
	wire, err := reply.Pack()
	if err != nil {
		return err
	}
	return write(wire)
}

func setDNSOptions(request, reply *dns.Msg, datagram bool) uint16 {
	var opt *dns.OPT
	malformed := false
	for section, records := range [...][]dns.RR{request.Extra, request.Answer, request.Ns} {
		for _, record := range records {
			if candidate, ok := record.(*dns.OPT); ok {
				malformed = malformed || opt != nil || section != 0 || candidate.Hdr.Name != "."
				opt = candidate
			}
		}
	}
	if opt == nil {
		return 0
	}
	response := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	response.SetUDPSize(dnsEDNSSize)
	switch {
	case malformed:
		reply.Rcode = dns.RcodeFormatError
		reply.Extra = []dns.RR{response}
	case opt.Version() != 0:
		reply.Rcode = dns.RcodeBadVers
		reply.Extra = []dns.RR{response}
	default:
		response.SetDo(opt.Do())
		if !datagram && dnsHasTCPKeepalive(request.Extra) {
			response.Option = []dns.EDNS0{&dns.EDNS0_TCP_KEEPALIVE{
				Timeout: uint16(dnsTCPTimeout / (100 * time.Millisecond)),
			}}
		}
		reply.Extra = append(reply.Extra, response)
		return opt.UDPSize()
	}
	return 0
}

func dnsHasTCPKeepalive(additional []dns.RR) bool {
	for _, record := range additional {
		opt, ok := record.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				return true
			}
		}
	}
	return false
}

func writeDNSError(write func([]byte) error, header dns.Header, code uint16) error {
	var wire [dnsHeaderSize]byte
	binary.BigEndian.PutUint16(wire[0:2], header.Id)
	flags := dnsResponseFlag | header.Bits&(dnsOpcodeMask|dnsQueryFlags) | code
	binary.BigEndian.PutUint16(wire[2:4], flags)
	return write(wire[:])
}

func dnsQuestionText(question dns.Question) string {
	typ := dns.Type(question.Qtype).String()
	switch question.Qtype {
	case dns.TypeNSAPPTR:
		typ = "NSAP-PTR"
	case dns.TypeIPSECKEY, dns.TypeNXNAME, dns.TypeAMTRELAY, dns.TypeRESINFO:
		typ = fmt.Sprintf("TYPE%d", question.Qtype)
	}
	return fmt.Sprintf(";%s\t%s\t %s\n", dns.Name(question.Name), dns.Class(question.Qclass), typ)
}
