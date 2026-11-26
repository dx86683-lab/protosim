package protocols

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/auxten/postgresql-parser/pkg/sql/parser"
)

type postgresExtendedSession struct {
	session  *SessionConnection
	pending  []byte
	deferred bool
	failed   bool
}

func (p *postgresExtendedSession) handle(kind byte, body string) error {
	switch kind {
	case 'Q':
		statement, residual, valid := strings.Cut(body, "\x00")
		if !valid || residual != "" {
			return errors.New("invalid PostgreSQL query frame")
		}
		logPostgres(p.session, "query", map[string]interface{}{"sql": statement})
		return p.ready(postgresQueryFixture(statement))
	case 'P':
		name, rest, terminated := strings.Cut(body, "\x00")
		query, types, queryOK := strings.Cut(rest, "\x00")
		if !terminated || !queryOK || query == "" || len(types) < 2 ||
			len(types)-2 != 4*int(binary.BigEndian.Uint16([]byte(types[:2]))) {
			return errors.New("invalid PostgreSQL Parse message")
		}
		logPostgres(p.session, "parse", map[string]interface{}{"name": name, "query": query})
		statements, err := parser.Parse(query)
		if err == nil && len(statements) == 0 {
			return errors.New("PostgreSQL Parse message contains no statement")
		}
		p.deferred = true
		if p.failed {
			return nil
		}
		if err != nil {
			return p.fail("42601", err.Error())
		}
		p.pending = postgresFrame(p.pending, '1', "")
		return p.checkPending()
	case 'B':
		portal, rest, terminated := strings.Cut(body, "\x00")
		name, formats, nameOK := strings.Cut(rest, "\x00")
		if !terminated || !nameOK || len(formats) < 6 {
			return errors.New("invalid PostgreSQL Bind message")
		}
		p.deferred = true
		logPostgres(p.session, "bind", map[string]interface{}{"dest_portal": portal, "prepare": name})
		if !p.failed {
			return p.missingStatement(name)
		}
	case 'D':
		if len(body) < 2 || body[0] != 'P' && body[0] != 'S' {
			return errors.New("invalid PostgreSQL Describe type")
		}
		name, rest, terminated := strings.Cut(body[1:], "\x00")
		if !terminated || rest != "" {
			return errors.New("invalid PostgreSQL Describe message")
		}
		p.deferred = true
		logPostgres(p.session, "describe", map[string]interface{}{"name": name})
		if body[0] == 'S' && !p.failed {
			return p.missingStatement(name)
		}
	case 'E':
		name, rest, terminated := strings.Cut(body, "\x00")
		if !terminated || len(rest) != 4 {
			return errors.New("invalid PostgreSQL Execute message")
		}
		logPostgres(p.session, "execute", map[string]interface{}{
			"portal": name, "max_rows": binary.BigEndian.Uint32([]byte(rest)),
		})
		if !p.failed {
			p.pending = postgresFrame(p.pending, 'C', "SET\x00")
			if !p.deferred {
				return p.ready(nil)
			}
			return p.checkPending()
		}
	case 'S':
		if body != "" {
			return errors.New("invalid PostgreSQL Sync message")
		}
		return p.ready(nil)
	default:
		if !p.failed {
			if err := p.fail("0A000", "unsupported message type"); err != nil || p.deferred {
				return err
			}
			return p.ready(nil)
		}
	}
	return nil
}

func (p *postgresExtendedSession) missingStatement(name string) error {
	return p.fail("26000", "prepared statement \""+name+"\" does not exist")
}

func (p *postgresExtendedSession) fail(code, message string) error {
	p.failed = true
	p.pending = append(p.pending, postgresError(code, message)...)
	return p.checkPending()
}

func (p *postgresExtendedSession) checkPending() error {
	if len(p.pending) > 65536 {
		return errors.New("too many pending PostgreSQL responses")
	}
	return nil
}

func (p *postgresExtendedSession) ready(extra []byte) error {
	reply := postgresFrame(append(p.pending, extra...), 'Z', "I")
	p.pending, p.deferred, p.failed = nil, false, false
	return writePostgres(p.session, string(reply))
}
