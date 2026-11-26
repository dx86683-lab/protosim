package protocols

import (
	"encoding/binary"
	"regexp"
	"strings"
	"time"
)

type mysqlSimulation struct {
	schema, table, current string
	sessionVariables       map[string]string
	deprecateEOF           bool
	autocommitOff, status  bool
	nextStatement          uint32
	statements             map[uint32]*mysqlStatement
	streamBytes            int
	connectionID           uint32
	connectionUser         string
	statementTime          time.Time
	foundRows              uint64
	rowCount               int64
}

type mysqlColumn struct {
	name string
	kind byte
}

var mysqlSelectTable = regexp.MustCompile(`(?i)^SELECT\s+\*\s+FROM\s+([.\w]+)(?:\s+LIMIT\s+([0-9]+))?$`)
var mysqlSetNames = regexp.MustCompile(`(?i)^SET\s+NAMES\s+(\w+)(?:\s+COLLATE\s+\w+)?$`)
var mysqlUserColumns = []mysqlColumn{{"name", 0xfc}, {"email", 0xfc}, {"phone_numbers", 0xfc}, {"created_at", 7}}
var mysqlSyntheticUsers = [...]struct{ name, email, phone string }{
	{"John Doe", "john@doe.com", "555-555-555"},
	{"John Doe", "johnalt@doe.com", ""},
	{"Jane Doe", "jane@doe.com", ""},
	{"Evil Bob", "evilbob@gmail.com", "666-666-666"},
}
var mysqlSyntheticUsersCreated = time.Now().UTC()

func (m *mysqlSimulation) useDatabase(db string) bool {
	if db != m.schema && db != "information_schema" {
		return false
	}
	m.current = db
	return true
}

func (m *mysqlSimulation) query(session *SessionConnection, input string) error {
	m.statementTime = time.Now()
	query := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(input), ";"))
	upper := strings.ToUpper(query)
	previousStatus := m.status
	m.status = !m.autocommitOff
	limit := m.selectLimit()
	if limit < 0 && len(upper) > 6 && upper[:6] == "SELECT" && strings.ContainsRune(" \t\r\n", rune(upper[6])) {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "Invalid syntax: negative limit"))
	}
	single := func(name, value string, kind byte) error {
		rows := [][]string{{value}}
		if limit == 0 {
			rows = nil
		}
		return m.writeRows(session, []mysqlColumn{{name, kind}}, rows)
	}
	switch upper {
	case "BEGIN", "START TRANSACTION", "COMMIT", "ROLLBACK":
		return writeMySQLPacket(session, 1, mysqlOK(m.status))
	case "SHOW WARNINGS":
		return m.writeRows(session, []mysqlColumn{{"Level", 0xfc}, {"Code", 3}, {"Message", 0xfc}}, nil)
	case "SELECT DATABASE()":
		if m.current == "" {
			rows := [][]string{nil}
			if limit == 0 {
				rows = nil
			}
			return m.writeRows(session, []mysqlColumn{{"DATABASE()", 0xfc}}, rows)
		}
		return single("DATABASE()", m.current, 0xfc)
	case "SELECT VERSION()":
		return single("VERSION()", "8.0.11", 0xfc)
	}
	if result, failure := m.schemaMetadata(query); failure != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(failure.code, "HY000", failure.message))
	} else if result != nil {
		return m.writeResult(session, mysqlColumns(result.columns), result.textRows, m.status)
	}
	if names := mysqlSetNames.FindStringSubmatch(query); names != nil {
		for _, name := range []string{"character_set_client", "character_set_connection", "character_set_results"} {
			m.storeSessionVariable(name, strings.ToLower(names[1]))
		}
		return m.writeSetResult(session, nil)
	}
	if assignment := mysqlSetVariables.FindStringSubmatch(query); assignment != nil {
		return m.writeSetResult(session, m.setSystemVariables(assignment[1]))
	}
	if strings.HasPrefix(upper, "USE ") {
		db := strings.Trim(strings.TrimSpace(query[4:]), "`")
		if !m.useDatabase(db) {
			return writeMySQLPacket(session, 1, mysqlUnknownDatabase(db))
		}
		return writeMySQLPacket(session, 1, mysqlOK(m.status))
	}
	if match := mysqlShowVariables.FindStringSubmatch(query); match != nil {
		return m.showSystemVariables(session, match[1], previousStatus)
	}
	if match := mysqlShowVariablesWhere.FindStringSubmatch(query); match != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "expecting \"EOF\" but got '"+match[1]+"' instead"))
	}
	if result, failure := m.catalogSelect(query, nil); failure != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(failure.code, "HY000", failure.message))
	} else if result != nil {
		return m.writeCatalogueResult(session, result, result.rows)
	}
	if match := mysqlSelectTable.FindStringSubmatch(query); match != nil {
		db, table, qualified := strings.Cut(match[1], ".")
		if !qualified {
			table, db = db, m.current
		}
		if db != m.schema || table != m.table {
			return writeMySQLPacket(session, 1, mysqlErrorPacket(1146, "HY000", "table not found: "+table))
		}
		var rows [][]string
		if match[2] != "0" && limit != 0 {
			user := mysqlSyntheticUsers[0]
			rows = [][]string{{user.name, user.email, user.phone, time.Now().UTC().Format("2006-01-02 15:04:05.999999")}}
		}
		return m.writeRows(session, mysqlUserColumns, rows)
	}
	return m.queryProjections(session, query)
}

func (m *mysqlSimulation) queryProjections(session *SessionConnection, query string) error {
	expressions, err := mysqlCompileProjections(query)
	if err != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", err.Error()))
	}
	columns := make([][]byte, 0, len(expressions))
	var row []byte
	for _, expr := range expressions {
		if expr.param {
			return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "query not supported by simulator"))
		}
		columns = append(columns, mysqlColumnPacket(expr.column, 33, expr.flags))
		if expr.column.kind == 6 {
			row = append(row, 0xfb)
		} else {
			value := expr.text
			if expr.variable != nil {
				value, err = m.systemVariableValue(expr.variable)
				if err != nil {
					return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", err.Error()))
				}
			}
			row = appendMySQLString(row, value)
		}
	}
	rows := [][]byte{row}
	if m.selectLimit() == 0 {
		rows = nil
	}
	return m.writeResult(session, columns, rows, m.status)
}

func mysqlOK(autocommit bool) []byte {
	packet := make([]byte, 7)
	if autocommit {
		packet[3] = 2
	}
	return packet
}

func mysqlUnknownDatabase(database string) []byte {
	return mysqlErrorPacket(1105, "HY000", "unknown error: database not found: "+database)
}

func mysqlErrorPacket(code uint16, state, message string) []byte {
	packet := binary.LittleEndian.AppendUint16([]byte{0xff}, code)
	packet = append(packet, '#')
	packet = append(packet, state...)
	return append(packet, message...)
}

func (m *mysqlSimulation) writeRows(session *SessionConnection, columns []mysqlColumn, rows [][]string) error {
	return m.writeRowsWithMetadataStatus(session, columns, rows, m.status)
}

func (m *mysqlSimulation) writeRowsWithMetadataStatus(session *SessionConnection, columns []mysqlColumn, rows [][]string, metadataStatus bool) error {
	return m.writeResult(session, mysqlColumns(columns), mysqlTextRows(rows), metadataStatus)
}

func mysqlTextRows(rows [][]string) [][]byte {
	packets := make([][]byte, 0, len(rows))
	for _, row := range rows {
		packet := []byte{0xfb} // NULL for a single-column result.
		if row != nil {
			packet = nil
			for _, value := range row {
				packet = appendMySQLString(packet, value)
			}
		}
		packets = append(packets, packet)
	}
	return packets
}

type mysqlReply struct {
	session  *SessionConnection
	sequence byte
}

func (r *mysqlReply) send(payload []byte) error {
	err := writeMySQLPacket(r.session, r.sequence, payload)
	r.sequence++
	return err
}

func mysqlColumnPacket(column mysqlColumn, charset byte, flags byte) []byte {
	packet := appendMySQLString([]byte{3, 'd', 'e', 'f', 0, 0, 0}, column.name)
	return append(packet, 0, 12, charset, 0, 0, 0, 0, 0, column.kind, flags, 0, 0, 0, 0)
}

func mysqlColumns(columns []mysqlColumn) [][]byte {
	packets := make([][]byte, 0, len(columns))
	for _, column := range columns {
		packets = append(packets, mysqlColumnPacket(column, 33, 0))
	}
	return packets
}

func (m *mysqlSimulation) endPacket(status bool) []byte {
	packet := []byte{0xfe, 0, 0, 0, 0}
	if status {
		packet[3] = 2
	}
	if m.deprecateEOF {
		packet = append(packet, 0, 0)
	}
	return packet
}

func (m *mysqlSimulation) writeResult(session *SessionConnection, columns, rows [][]byte, metadataStatus bool) error {
	reply := mysqlReply{session: session, sequence: 1}
	if err := reply.send([]byte{byte(len(columns))}); err != nil {
		return err
	}
	for _, column := range columns {
		if err := reply.send(column); err != nil {
			return err
		}
	}
	if !m.deprecateEOF {
		if err := reply.send(m.endPacket(metadataStatus)); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if err := reply.send(row); err != nil {
			return err
		}
	}
	if err := reply.send(m.endPacket(m.status)); err != nil {
		return err
	}
	m.foundRows = uint64(len(rows))
	m.rowCount = -1
	return nil
}

func (m *mysqlSimulation) fieldList(session *SessionConnection, input string) error {
	table, _, _ := strings.Cut(input, "\x00")
	reply := mysqlReply{session: session, sequence: 1}
	if m.current != m.schema || table != m.table {
		return reply.send(mysqlErrorPacket(1146, "HY000", "table not found: "+table))
	}
	for _, column := range mysqlColumns(mysqlUserColumns) {
		if err := reply.send(append(column, 0)); err != nil {
			return err
		}
	}
	return reply.send(m.endPacket(!m.autocommitOff))
}

func appendMySQLString(packet []byte, value string) []byte {
	switch length := len(value); {
	case length < 251:
		packet = append(packet, byte(length))
	case length <= 65535:
		packet = binary.LittleEndian.AppendUint16(append(packet, 0xfc), uint16(length))
	default:
		packet = append(packet, 0xfd, byte(length), byte(length>>8), byte(length>>16))
	}
	return append(packet, value...)
}
