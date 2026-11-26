package protocols

import (
	"fmt"
	"net/mail"
	"strconv"
	"strings"
)

func (m *imapMessage) header(name string) string {
	return imapHeaderValue(m.headers, name)
}

func imapNString(value string) string {
	if value == "" {
		return "NIL"
	}
	return strconv.Quote(value)
}

func (m *imapMessage) envelope() string {
	if m.seed {
		return imapEnvelope
	}
	from := imapAddressList(m.header("From"))
	sender := imapAddressList(m.header("Sender"))
	if sender == "NIL" {
		sender = from
	}
	replyTo := imapAddressList(m.header("Reply-To"))
	if replyTo == "NIL" {
		replyTo = from
	}
	fields := []string{imapNString(m.header("Date")), imapNString(m.header("Subject")), from, sender, replyTo,
		imapAddressList(m.header("To")), imapAddressList(m.header("Cc")), imapAddressList(m.header("Bcc")),
		imapNString(m.header("In-Reply-To")), imapNString(m.header("Message-ID"))}
	return "(" + strings.Join(fields, " ") + ")"
}

func imapAddressList(value string) string {
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return "NIL"
	}
	var fields []string
	for _, address := range addresses {
		name, domain, _ := strings.Cut(address.Address, "@")
		fields = append(fields, fmt.Sprintf("(%s NIL %s %s)", imapNString(address.Name), imapNString(name), imapNString(domain)))
	}
	return "(" + strings.Join(fields, " ") + ")"
}

func (m *imapMessage) structure(extended bool) string {
	if m.seed {
		if extended {
			return imapStructure + " NIL NIL NIL NIL"
		}
		return imapStructure
	}
	return m.mimeRoot().structure(extended)
}
