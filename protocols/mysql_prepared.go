package protocols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	mysqlMaxStatements  = 128
	mysqlMaxProjections = 64
	mysqlMaxStreamBytes = 64 << 10
)

const mysqlProjectionNumber = `[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?`

var mysqlProjectionPattern = regexp.MustCompile(`(?i)^(\?|NULL|TRUE|FALSE|'(?:[^']|'')*'|` + mysqlProjectionNumber + `|` + mysqlVariableToken + `)(?:\s+(?:(AS)\s+)?(\w+|'(?:[^']|'')*'|"(?:[^"]|"")*"|` + "`(?:[^`]|``)*`" + `))?$`)
var mysqlSelectName = regexp.MustCompile(`(?i)^SELECT\s+name\s+FROM\s+([.\w]+)$`)
var errMySQLExecuteArgs = errors.New("Incorrect arguments to mysqld_stmt_execute")

type mysqlExpression struct {
	column       mysqlColumn
	value        []byte
	text         string
	flags        byte
	charset      byte
	param        bool
	variable     *mysqlVariableReference
	contextError string
}

type mysqlParameter struct {
	kind   byte
	flags  byte
	bound  bool
	stream []byte
}

type mysqlStatement struct {
	expressions []mysqlExpression
	parameters  []mysqlParameter
	tableRows   [][]byte
	metadataSQL string
	catalogSQL  string
}

func (m *mysqlSimulation) compileStatement(query string) (*mysqlStatement, error) {
	stmt := &mysqlStatement{}
	if match := mysqlSelectName.FindStringSubmatch(query); match != nil {
		database, table, qualified := strings.Cut(match[1], ".")
		if !qualified {
			database, table = m.current, database
		}
		if database != m.schema || table != m.table {
			return nil, errors.New("unknown error: table not found: " + table)
		}
		stmt.expressions = []mysqlExpression{{column: mysqlUserColumns[0]}}
		for _, user := range mysqlSyntheticUsers {
			stmt.tableRows = append(stmt.tableRows, appendMySQLString([]byte{0, 0}, user.name))
		}
		return stmt, nil
	}
	expressions, err := mysqlCompileProjections(query)
	if err != nil {
		return nil, err
	}
	stmt.expressions = expressions
	for _, expr := range expressions {
		if expr.param {
			stmt.parameters = append(stmt.parameters, mysqlParameter{})
		}
	}
	return stmt, nil
}

func mysqlCompileProjections(query string) ([]mysqlExpression, error) {
	projections := mysqlSelectProjections(query)
	if len(projections) == 0 || len(projections) > mysqlMaxProjections {
		return nil, errors.New("query not supported by simulator")
	}
	expressions := make([]mysqlExpression, 0, len(projections))
	for _, projection := range projections {
		match := mysqlProjectionPattern.FindStringSubmatch(projection)
		if match == nil {
			return nil, errors.New("query not supported by simulator")
		}
		var expr mysqlExpression
		var err error
		if strings.HasPrefix(match[1], "@@") {
			expr, err = mysqlSystemVariableProjection(match[1], match[3])
		} else {
			expr, err = mysqlProjection(match[1], match[2], match[3])
		}
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, expr)
	}
	return expressions, nil
}

func mysqlProjection(value, as, alias string) (mysqlExpression, error) {
	var expr mysqlExpression
	switch lower := strings.ToLower(value); {
	case value == "?":
		expr.column.kind, expr.param = 0xfc, true
	case value[0] == '\'':
		value = mysqlUnquoteProjection(value)
		expr.column.kind, expr.value = 0xfc, appendMySQLString(nil, value)
		expr.text = value
	case lower == "null":
		expr.column.kind, expr.flags = 6, 0x80
	case lower == "true":
		expr.column.kind, expr.value, expr.text = 1, []byte{1}, "1"
	case lower == "false":
		expr.column.kind, expr.value, expr.text = 1, []byte{0}, "0"
	case strings.ContainsAny(value, ".eE"):
		number, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return expr, errors.New("query not supported by simulator")
		}
		expr.column.kind, expr.value = 5, binary.LittleEndian.AppendUint64(nil, math.Float64bits(number))
		expr.text = strconv.FormatFloat(number, 'f', -1, 64)
	default:
		expr.column.kind, expr.flags, expr.value, expr.text = mysqlLiteralInteger(strings.TrimPrefix(value, "+"))
		if expr.value == nil {
			return expr, errors.New("query not supported by simulator")
		}
	}
	expr.column.name = mysqlUnquoteProjection(alias)
	if expr.column.name == "" {
		expr.column.name = value
		if alias != "" && as != "" {
			expr.column.name += " " + as
		}
	}
	return expr, nil
}

func mysqlUnquoteProjection(value string) string {
	if len(value) >= 2 && strings.ContainsRune("'\"`", rune(value[0])) {
		quote := value[:1]
		return strings.ReplaceAll(value[1:len(value)-1], quote+quote, quote)
	}
	return value
}

func mysqlSelectProjections(query string) []string {
	if len(query) < 7 || !strings.EqualFold(query[:6], "SELECT") || !strings.ContainsRune(" \t\r\n", rune(query[6])) {
		return nil
	}
	return mysqlSplitExpressions(strings.TrimSpace(query[6:]))
}

func mysqlSplitExpressions(body string) []string {
	var fields []string
	var quote rune
	depth := 0
	start := 0
	for i, ch := range body {
		switch {
		case ch == quote:
			quote = 0
		case quote != 0:
			continue
		case ch == '\'' || ch == '"' || ch == '`':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
		case ch == ',' && depth == 0:
			fields = append(fields, strings.TrimSpace(body[start:i]))
			start = i + 1
		}
	}
	if quote != 0 {
		return nil
	}
	return append(fields, strings.TrimSpace(body[start:]))
}

func mysqlLiteralInteger(value string) (kind, flags byte, encoded []byte, text string) {
	negative := strings.HasPrefix(value, "-")
	var bits uint64
	if negative {
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, 0, nil, ""
		}
		bits = uint64(number)
		text = strconv.FormatInt(number, 10)
	} else {
		var err error
		bits, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, 0, nil, ""
		}
		text = strconv.FormatUint(bits, 10)
	}
	n := int64(bits)
	switch {
	case negative && n >= math.MinInt8 || !negative && bits <= math.MaxUint8:
		kind, encoded = 1, []byte{byte(bits)}
		if !negative && bits > math.MaxInt8 {
			flags = 0x20
		}
	case negative && n >= math.MinInt16 || !negative && bits <= math.MaxUint16:
		kind, encoded = 2, binary.LittleEndian.AppendUint16(nil, uint16(bits))
		if !negative && bits > math.MaxInt16 {
			flags = 0x20
		}
	case negative && n >= math.MinInt32 || !negative && bits <= math.MaxUint32:
		kind, encoded = 3, binary.LittleEndian.AppendUint32(nil, uint32(bits))
		if !negative && bits > math.MaxInt32 {
			flags = 0x20
		}
	default:
		kind, encoded = 8, binary.LittleEndian.AppendUint64(nil, bits)
		if !negative && bits > math.MaxInt64 {
			flags = 0x20
		}
	}
	return kind, flags, encoded, text
}

func (m *mysqlSimulation) prepare(session *SessionConnection, input string) error {
	query := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(input), ";"))
	var stmt *mysqlStatement
	bindings := &mysqlCatalogBindings{preparing: true}
	if metadata, failure := m.preparedMetadata(query); failure != nil {
		// The reference reserves an identifier even when preparing metadata fails.
		m.nextStatement++
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "unknown error: "+failure.message))
	} else if metadata != nil {
		stmt = &mysqlStatement{metadataSQL: query}
		for _, column := range metadata.columns {
			stmt.expressions = append(stmt.expressions, mysqlExpression{column: column})
		}
	} else if catalog, failure := m.catalogSelect(query, bindings); failure != nil {
		m.nextStatement++
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "unknown error: "+failure.message))
	} else if catalog != nil {
		stmt = &mysqlStatement{catalogSQL: query, parameters: make([]mysqlParameter, bindings.next)}
		for _, field := range catalog.columns {
			stmt.expressions = append(stmt.expressions, mysqlExpression{
				column: mysqlColumn{field.label, field.kind}, flags: field.flags, charset: field.charset,
			})
		}
	} else {
		var err error
		stmt, err = m.compileStatement(query)
		if err != nil {
			message := err.Error()
			if _, ok := err.(mysqlSystemVariableError); ok {
				message = "unknown error: " + message
			}
			return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", message))
		}
	}
	if len(m.statements) >= mysqlMaxStatements {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1461, "42000", "simulated prepared statement limit reached"))
	}
	if m.statements == nil {
		m.statements = make(map[uint32]*mysqlStatement)
	}
	m.nextStatement++
	m.statements[m.nextStatement] = stmt
	reply := mysqlReply{session: session, sequence: 1}
	le := binary.LittleEndian
	header := le.AppendUint32([]byte{0}, m.nextStatement)
	header = le.AppendUint16(header, uint16(len(stmt.expressions)))
	header = le.AppendUint16(header, uint16(len(stmt.parameters)))
	if err := reply.send(append(header, 0, 0, 0)); err != nil {
		return err
	}
	for range stmt.parameters {
		if err := reply.send(mysqlColumnPacket(mysqlColumn{"?", 0xfd}, 63, 0x80)); err != nil {
			return err
		}
	}
	if len(stmt.parameters) != 0 && !m.deprecateEOF {
		if err := reply.send(m.endPacket(m.status)); err != nil {
			return err
		}
	}
	for _, expr := range stmt.expressions {
		charset := expr.charset
		if charset == 0 {
			charset = 33
		}
		if err := reply.send(mysqlColumnPacket(expr.column, charset, expr.flags)); err != nil {
			return err
		}
	}
	if !m.deprecateEOF {
		return reply.send(m.endPacket(m.status))
	}
	return nil
}

func (m *mysqlSimulation) execute(session *SessionConnection, input []byte) error {
	m.statementTime = time.Now()
	if len(input) < 9 {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1210, "HY000", errMySQLExecuteArgs.Error()))
	}
	stmt := m.statements[binary.LittleEndian.Uint32(input)]
	if stmt == nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(2014, "HY000", "statement ID is not found from record"))
	}
	if stmt.metadataSQL != "" {
		// Resolve the current database and session variables again at execution.
		metadata, failure := m.preparedMetadata(stmt.metadataSQL)
		if failure != nil {
			return writeMySQLPacket(session, 1, mysqlErrorPacket(failure.code, "HY000", failure.message))
		}
		previousStatus := m.status
		m.status = !m.autocommitOff
		metadataStatus := m.status
		if metadata.usePreviousStatus {
			metadataStatus = previousStatus
		}
		return m.writeResult(session, mysqlColumns(metadata.columns), metadata.binaryRows(), metadataStatus)
	}
	defer m.discardStreams(stmt)
	if stmt.catalogSQL != "" {
		return m.executeCatalog(session, stmt, input[9:])
	}
	columns, rows, err := stmt.result(m, input[9:])
	if err != nil {
		code := uint16(2027)
		if err == errMySQLExecuteArgs {
			code = 1210
		} else if _, ok := err.(mysqlSystemVariableError); ok {
			code = 1105
		}
		return writeMySQLPacket(session, 1, mysqlErrorPacket(code, "HY000", err.Error()))
	}
	// The reference returns rows inline even when the client requests a cursor.
	limit := m.selectLimit()
	if limit < 0 {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "Invalid syntax: negative limit"))
	}
	if limit < int64(len(rows)) {
		rows = rows[:limit]
	}
	m.status = !m.autocommitOff
	return m.writeResult(session, columns, rows, m.status)
}

func (s *mysqlStatement) result(model *mysqlSimulation, input []byte) (columns, rows [][]byte, err error) {
	parameters, err := s.bind(input)
	if err != nil {
		return nil, nil, err
	}
	columnCount := len(s.expressions)
	row := make([]byte, 1+(columnCount+9)/8)
	columns = make([][]byte, 0, columnCount)
	index := 0
	for position, expr := range s.expressions {
		charset, flags, kind, value := byte(33), expr.flags, expr.column.kind, expr.value
		if expr.param {
			p := parameters[index]
			index++
			kind, value = p.kind, p.data
			if p.binary {
				charset, flags = 63, 0x80
			}
		} else if expr.variable != nil {
			value, err = model.binarySystemVariable(expr)
			if err != nil {
				return nil, nil, err
			}
		}
		if kind == 6 {
			row[1+(position+2)/8] |= 1 << ((position + 2) % 8)
			flags = 0x80
		}
		columns = append(columns, mysqlColumnPacket(mysqlColumn{expr.column.name, kind}, charset, flags))
		row = append(row, value...)
	}
	if s.tableRows != nil {
		return columns, s.tableRows, nil
	}
	return columns, [][]byte{row}, nil
}

type mysqlBoundParameter struct {
	kind   byte
	data   []byte
	binary bool
}

func (s *mysqlStatement) bind(input []byte) ([]mysqlBoundParameter, error) {
	count := len(s.parameters)
	if count == 0 {
		return nil, nil
	}
	bitmapSize := (count + 7) / 8
	if len(input) <= bitmapSize || input[bitmapSize] > 1 {
		return nil, errMySQLExecuteArgs
	}
	nulls, updateTypes := input[:bitmapSize], input[bitmapSize] == 1
	input = input[bitmapSize+1:]
	var types []byte
	if updateTypes {
		if len(input) < 2*count {
			return nil, errMySQLExecuteArgs
		}
		types, input = input[:2*count], input[2*count:]
	}
	values := make([]mysqlBoundParameter, count)
	for i, param := range s.parameters {
		if updateTypes {
			param.kind, param.flags, param.bound = types[2*i], types[2*i+1], true
		}
		if param.stream != nil {
			values[i] = mysqlBoundParameter{kind: 0xfd, data: appendMySQLString(nil, string(param.stream)), binary: true}
		} else if nulls[i/8]&(1<<(i%8)) != 0 || param.kind == 6 {
			values[i].kind = 6
		} else {
			if !param.bound {
				return nil, errMySQLExecuteArgs
			}
			value, width, err := mysqlParameterValue(param, input)
			if err != nil {
				return nil, err
			}
			values[i], input = value, input[width:]
		}
	}
	if len(input) != 0 {
		return nil, errMySQLExecuteArgs
	}
	if updateTypes {
		for i := range s.parameters {
			param := &s.parameters[i]
			param.kind, param.flags, param.bound = types[2*i], types[2*i+1], true
		}
	}
	return values, nil
}

func mysqlParameterValue(param mysqlParameter, input []byte) (mysqlBoundParameter, int, error) {
	le := binary.LittleEndian
	var width int
	switch param.kind {
	case 1:
		width = 1
	case 2, 13:
		width = 2
	case 3, 4, 9:
		width = 4
	case 5, 8:
		width = 8
	case 0x07, 0x0a, 0x0b, 0x0c, 0x11, 0x12, 0x13:
		return mysqlTemporalParameter(param.kind, input)
	case 0, 0x0f, 0x10, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff:
		value, width := mysqlLengthEncodedParameter(input)
		if width == 0 {
			return mysqlBoundParameter{}, 0, errMySQLExecuteArgs
		}
		return mysqlBoundParameter{kind: 0xfd, data: appendMySQLString(nil, string(value)), binary: true}, width, nil
	default:
		return mysqlBoundParameter{}, 0, fmt.Errorf("MySQLToType(%d,%d) failed: unsupported type: %d", param.kind, param.flags, param.kind)
	}
	if len(input) < width {
		return mysqlBoundParameter{}, 0, errMySQLExecuteArgs
	}
	if param.kind == 4 {
		bits := math.Float64bits(float64(math.Float32frombits(le.Uint32(input))))
		return mysqlBoundParameter{kind: 5, data: le.AppendUint64(nil, bits)}, width, nil
	}
	if param.kind == 5 {
		return mysqlBoundParameter{kind: 5, data: input[:width]}, width, nil
	}
	// The reference widens integer parameters to eight bytes and zero-extends narrow values.
	value := make([]byte, 8)
	copy(value, input[:width])
	return mysqlBoundParameter{kind: 8, data: value}, width, nil
}

func mysqlTemporalParameter(kind byte, input []byte) (mysqlBoundParameter, int, error) {
	if len(input) == 0 || int(input[0]) >= len(input) {
		return mysqlBoundParameter{}, 0, errMySQLExecuteArgs
	}
	width := int(input[0]) + 1
	payload := input[1:width]
	var text string
	if kind == 0x0b || kind == 0x13 {
		text = mysqlTimeParameter(payload)
	} else {
		text = mysqlDateParameter(payload)
	}
	if text == "" {
		return mysqlBoundParameter{}, 0, errMySQLExecuteArgs
	}
	return mysqlBoundParameter{kind: 0xfd, data: appendMySQLString(nil, text)}, width, nil
}

func mysqlDateParameter(value []byte) string {
	switch len(value) {
	case 0:
		return " "
	case 4, 7, 11:
		text := fmt.Sprintf("%d-%d-%d", binary.LittleEndian.Uint16(value), value[2], value[3])
		if len(value) >= 7 {
			text += fmt.Sprintf(" %d:%d:%d", value[4], value[5], value[6])
		}
		if len(value) == 11 {
			text += fmt.Sprintf(".%06d", binary.LittleEndian.Uint32(value[7:]))
		}
		return text
	}
	return ""
}

func mysqlTimeParameter(value []byte) string {
	switch len(value) {
	case 0:
		return "00:00:00"
	case 8, 12:
		hours := uint64(binary.LittleEndian.Uint32(value[1:]))*24 + uint64(value[5])
		text := fmt.Sprintf("%d:%d:%d", hours, value[6], value[7])
		if value[0] == 1 {
			text = "-" + text
		}
		if len(value) == 12 {
			text += fmt.Sprintf(".%06d", binary.LittleEndian.Uint32(value[8:]))
		}
		return text
	}
	return ""
}

func (m *mysqlSimulation) addStream(input []byte) bool {
	if len(input) < 6 {
		return false
	}
	le := binary.LittleEndian
	stmt := m.statements[le.Uint32(input)]
	index := int(le.Uint16(input[4:]))
	if stmt == nil || index >= len(stmt.parameters) || len(input)-6 > mysqlMaxStreamBytes-m.streamBytes {
		return false
	}
	param := &stmt.parameters[index]
	if param.stream == nil {
		param.stream = []byte{}
	}
	param.stream = append(param.stream, input[6:]...)
	m.streamBytes += len(input) - 6
	return true
}

func (m *mysqlSimulation) discardStreams(stmt *mysqlStatement) {
	for i := range stmt.parameters {
		m.streamBytes -= len(stmt.parameters[i].stream)
		stmt.parameters[i].stream = nil
	}
}

func mysqlLengthEncodedParameter(input []byte) ([]byte, int) {
	if len(input) == 0 {
		return nil, 0
	}
	var prefix int
	var length uint64
	switch input[0] {
	case 0xfc:
		if len(input) >= 3 {
			prefix, length = 3, uint64(binary.LittleEndian.Uint16(input[1:]))
		}
	case 0xfd:
		if len(input) >= 4 {
			prefix, length = 4, uint64(input[1])|uint64(input[2])<<8|uint64(input[3])<<16
		}
	case 0xfe:
		if len(input) >= 9 {
			prefix, length = 9, binary.LittleEndian.Uint64(input[1:])
		}
	default:
		if input[0] < 0xfb {
			prefix, length = 1, uint64(input[0])
		}
	}
	if prefix == 0 || length > uint64(len(input)-prefix) {
		return nil, 0
	}
	width := prefix + int(length)
	return input[prefix:width], width
}
