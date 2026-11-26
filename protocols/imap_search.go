package protocols

import (
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

type imapSearch struct {
	tokens   []imapArgumentToken
	index    int
	message  *imapMessage
	sequence uint32
}

var errIMAPSearchFields = errors.New("imap: no enough fields for search key")

func imapSearchReply(tag, done, argument string, uid bool, messages []imapMessage) string {
	if strings.TrimSpace(argument) == "" {
		return tag + " BAD Missing search criteria\r\n"
	}
	tokens, ok := tokenizeIMAPArguments(argument)
	if !ok {
		return tag + " BAD " + errIMAPSearchFields.Error() + "\r\n"
	}
	if len(tokens) != 0 && strings.EqualFold(tokens[0].text, "CHARSET") {
		header := imapSearch{tokens: tokens, index: 1}
		if _, err := header.argument(); err != nil {
			return tag + " BAD " + err.Error() + "\r\n"
		}
		tokens = tokens[header.index:]
	}
	var result strings.Builder
	result.WriteString("* SEARCH")
	for i := 0; i < max(1, len(messages)); i++ {
		search := imapSearch{tokens: tokens, sequence: uint32(i + 1), message: &imapMessage{}}
		if len(messages) != 0 {
			search.message = &messages[i]
		}
		matched, err := search.group(false, 0)
		if err != nil {
			return tag + " BAD " + err.Error() + "\r\n"
		}
		if matched && len(messages) != 0 {
			id := search.sequence
			if uid {
				id = search.message.uid
			}
			result.WriteByte(' ')
			result.WriteString(strconv.FormatUint(uint64(id), 10))
		}
	}
	return result.String() + "\r\n" + done
}

func (p *imapSearch) group(nested bool, depth int) (bool, error) {
	result := true
	for p.index < len(p.tokens) {
		if p.tokens[p.index].delimiter == ')' {
			if !nested {
				return false, errIMAPSearchFields
			}
			p.index++
			return result, nil
		}
		match, err := p.criterion(depth)
		if err != nil {
			return false, err
		}
		result = result && match
	}
	if nested {
		return false, errIMAPSearchFields
	}
	return result, nil
}

func (p *imapSearch) argument() (string, error) {
	if p.index >= len(p.tokens) || p.tokens[p.index].delimiter != 0 {
		return "", errIMAPSearchFields
	}
	text := p.tokens[p.index].text
	p.index++
	return text, nil
}

func (p *imapSearch) criterion(depth int) (bool, error) {
	if depth > 32 {
		return false, errors.New("search criteria nested too deeply")
	}
	if p.index >= len(p.tokens) || p.tokens[p.index].delimiter == ')' {
		return true, nil // An absent operand is an empty criterion.
	}
	if p.tokens[p.index].delimiter == '(' {
		p.index++
		return p.group(true, depth+1)
	}
	key, _ := p.argument()
	switch strings.ToUpper(key) {
	case "ALL":
		return true, nil
	case "NEW":
		return p.message.hasFlag(`\Recent`) && !p.message.hasFlag(`\Seen`), nil
	case "OLD":
		return !p.message.hasFlag(`\Recent`), nil
	case "SEEN", "RECENT", "ANSWERED", "DELETED", "FLAGGED", "DRAFT":
		return p.message.hasFlag("\\" + key), nil
	case "UNSEEN", "UNANSWERED", "UNDELETED", "UNFLAGGED", "UNDRAFT":
		return !p.message.hasFlag("\\" + key[2:]), nil
	case "NOT":
		match, err := p.criterion(depth + 1)
		return !match, err
	case "OR":
		first, err := p.criterion(depth + 1)
		if err != nil {
			return false, err
		}
		second, err := p.criterion(depth + 1)
		return first || second, err
	case "UID", "KEYWORD", "UNKEYWORD", "LARGER", "SMALLER", "BEFORE", "ON", "SINCE",
		"SENTBEFORE", "SENTON", "SENTSINCE", "BODY", "TEXT", "HEADER", "FROM", "TO", "CC", "BCC", "SUBJECT":
		return p.fieldCriterion(strings.ToUpper(key))
	default:
		return imapSequenceMatch(key, p.sequence)
	}
}

func (p *imapSearch) fieldCriterion(key string) (bool, error) {
	value, err := p.argument()
	if err != nil {
		return false, err
	}
	switch key {
	case "UID":
		return imapSequenceMatch(value, p.message.uid)
	case "KEYWORD", "UNKEYWORD":
		hasFlag := p.message.hasFlag(value)
		return hasFlag == (key == "KEYWORD"), nil
	case "LARGER", "SMALLER":
		size, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return false, err
		}
		messageSize := uint64(len(p.message.headers) + len(p.message.text))
		return (key == "LARGER" && messageSize > size) || (key == "SMALLER" && messageSize < size), nil
	case "BEFORE", "ON", "SINCE", "SENTBEFORE", "SENTON", "SENTSINCE":
		return imapSearchDate(key, value, p.message)
	case "BODY":
		return imapContains(p.message.text, value), nil
	case "TEXT":
		return imapContains(p.message.headers+p.message.text, value), nil
	case "HEADER":
		needle, err := p.argument()
		if err != nil {
			return false, err
		}
		return p.message.headerContains(value, needle), nil
	default:
		return p.message.headerContains(key, value), nil
	}
}

func imapSearchDate(key, value string, message *imapMessage) (bool, error) {
	date, err := time.Parse("_2-Jan-2006", value)
	if err != nil {
		return false, err
	}
	messageDate := message.date
	if suffix, sent := strings.CutPrefix(key, "SENT"); sent {
		key = suffix
		messageDate, err = mail.ParseDate(message.header("Date"))
		if err != nil {
			return false, nil
		}
	}
	year, month, day := messageDate.Date()
	messageDay := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	switch key {
	case "BEFORE":
		return messageDay.Before(date), nil
	case "ON":
		return messageDay.Equal(date), nil
	default:
		return !messageDay.Before(date), nil
	}
}

func (m *imapMessage) headerContains(name, needle string) bool {
	for _, line := range imapHeaderFields(m.headers) {
		field, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(name, field) {
			return imapContains(strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "")), needle)
		}
	}
	return false
}

func imapContains(text, needle string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(needle))
}
