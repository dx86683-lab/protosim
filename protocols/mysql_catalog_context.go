package protocols

import (
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const mysqlCatalogueBareFunction = `(?:CURRENT_TIMESTAMP|CURRENT_DATE|CURRENT_TIME)`
const mysqlCatalogueFunction = `[a-z_]\w*\s*\(\s*(?:[+-]?\d+|` + mysqlCatalogProjectionString + `)?\s*\)`

const mysqlCatalogueSelectStart = `(?is)^SELECT\s+(?:(DISTINCT)\s+)?`

var mysqlCatalogueNoFrom = regexp.MustCompile(mysqlCatalogueSelectStart + `(.+?)` + mysqlCatalogSelectTail)
var mysqlCatalogueSelectHead = regexp.MustCompile(mysqlCatalogueSelectStart)
var mysqlCatalogueCalcRows = regexp.MustCompile(`(?i)^(SELECT\s+(?:DISTINCT\s+)?)(SQL_CALC_FOUND_ROWS\s+)`)
var mysqlCatalogueDistinct = regexp.MustCompile(`(?i)^DISTINCT\b`)

func mysqlCatalogueSelectOptions(query string) (string, bool, *mysqlMetadataError) {
	match := mysqlCatalogueCalcRows.FindStringSubmatchIndex(query)
	if match == nil {
		return query, false, nil
	}
	if mysqlCatalogueDistinct.MatchString(query[match[5]:]) {
		return query, false, mysqlDiagnosticAt(query, match[5], "syntax error", "")
	}
	// Keep token offsets relative to the original input.
	query = query[:match[4]] + strings.Repeat(" ", match[5]-match[4]) + query[match[5]:]
	return query, true, nil
}

func mysqlCatalogueFunctionName(raw string) (name, argument string) {
	name, argument, _ = strings.Cut(raw, "(")
	return strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(strings.TrimSuffix(argument, ")"))
}

func mysqlCatalogueHasContext(projection string) bool {
	for _, expression := range mysqlSplitExpressions(projection) {
		if mysqlGroupConcatExpression.MatchString(expression) {
			return true
		}
		match := mysqlCatalogScalar.FindStringSubmatch(expression)
		if match == nil {
			continue
		}
		name, _ := mysqlCatalogueFunctionName(match[1])
		switch name {
		case "now", "current_timestamp", "utc_timestamp", "current_date", "curdate", "current_time", "curtime",
			"user", "current_user", "session_user", "system_user", "current_role", "connection_id", "found_rows", "row_count":
			return true
		}
	}
	return false
}

func (m *mysqlSimulation) catalogNoSource(query string, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope, calcRows, subquery bool) (*mysqlCatalogResult, *mysqlMetadataError) {
	if mysqlCatalogChainPrefix.MatchString(query) {
		return nil, nil
	}
	match := mysqlCatalogueNoFrom.FindStringSubmatch(query)
	if match != nil && (match[6] != "" || strings.Contains(strings.ToUpper(query), "GROUP_CONCAT")) {
		if parsed := mysqlCatalogueNoSourceSyntax(query); parsed != nil {
			match = parsed
		}
	}
	if match == nil || !subquery && !calcRows && match[6] == "" && !mysqlCatalogueHasContext(match[2]) {
		return nil, nil
	}
	source := mysqlCatalogSource{depth: depth, outer: outer, calcFoundRows: calcRows}
	if bindings == nil || !bindings.preparing {
		source.rows = []mysqlCatalogRecord{{}}
	}
	return m.selectCatalogue(match[1], match[2], match[3:], source, bindings, reserveMySQLProjectionBindings(match[2], bindings))
}

func mysqlCatalogueNoSourceSyntax(query string) []string {
	head := mysqlCatalogueSelectHead.FindStringSubmatch(query)
	if head == nil {
		return nil
	}
	body := query[len(head[0]):]
	_, end, balanced := mysqlCatalogScanSources(body)
	if !balanced {
		return nil
	}
	tail := mysqlCatalogJoinTail(body[end:])
	if tail == nil {
		return nil
	}
	return append([]string{query, head[1], strings.TrimSpace(body[:end])}, tail...)
}

func (m *mysqlSimulation) catalogueFunction(expr *mysqlExpression, raw string) *mysqlMetadataError {
	name, arg := mysqlCatalogueFunctionName(raw)
	stamp := m.statementTime
	if stamp.IsZero() {
		stamp = time.Now()
	}
	switch name {
	case "database", "schema":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		if m.current == "" {
			return nil
		}
		expr.text = m.current
	case "version":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.text = "8.0.11"
	case "now", "current_timestamp", "utc_timestamp":
		expr.column.kind, expr.flags = 12, 0x80
		if arg != "" {
			if name != "now" {
				return &mysqlMetadataError{1105, "unsupported syntax: " + raw}
			}
			if arg[0] == '\'' || arg[0] == '"' {
				expr.contextError = "invalid type: LONGTEXT"
				return nil
			}
			precision, err := strconv.Atoi(arg)
			if err != nil || precision < 0 || precision > 6 {
				expr.contextError = "precision out of range for now"
				return nil
			}
		}
		stamp = stamp.UTC()
		expr.text = stamp.Format("2006-01-02 15:04:05.999999")
		expr.value = appendMySQLCatalogueDateTime(nil, stamp)
		return nil
	case "curdate", "current_date":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.text = stamp.Local().Format("2006-01-02")
	case "curtime", "current_time":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.text = stamp.Local().Format("15:04:05")
	case "user", "current_user":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.text = m.connectionUser
	case "connection_id":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.column.kind, expr.flags = 3, 0x20
		expr.text = strconv.FormatUint(uint64(m.connectionID), 10)
		expr.value = binary.LittleEndian.AppendUint32(nil, m.connectionID)
		return nil
	case "found_rows":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.column.kind, expr.flags = 8, 0x20
		expr.text = strconv.FormatUint(m.foundRows, 10)
		expr.value = binary.LittleEndian.AppendUint64(nil, m.foundRows)
		return nil
	case "row_count":
		if arg != "" {
			return mysqlCatalogUnsupported()
		}
		expr.column.kind, expr.flags = 8, 0x20
		if m.rowCount < 0 {
			expr.contextError = "-1 out of range for BIGINT UNSIGNED"
		} else {
			expr.text = strconv.FormatInt(m.rowCount, 10)
			expr.value = binary.LittleEndian.AppendUint64(nil, uint64(m.rowCount))
		}
		return nil
	case "current_database", "session_user", "system_user", "current_role":
		return &mysqlMetadataError{1105, "function: '" + name + "' not found"}
	default:
		return mysqlCatalogUnsupported()
	}
	expr.value = appendMySQLString(nil, expr.text)
	return nil
}

func appendMySQLCatalogueDateTime(row []byte, stamp time.Time) []byte {
	microseconds := uint32(stamp.Nanosecond() / 1000)
	size := byte(7)
	if microseconds != 0 {
		size = 11
	}
	row = append(row, size)
	row = binary.LittleEndian.AppendUint16(row, uint16(stamp.Year()))
	row = append(row, byte(stamp.Month()), byte(stamp.Day()), byte(stamp.Hour()), byte(stamp.Minute()), byte(stamp.Second()))
	if microseconds != 0 {
		row = binary.LittleEndian.AppendUint32(row, microseconds)
	}
	return row
}

func (m *mysqlSimulation) writeCatalogueResult(session *SessionConnection, result *mysqlCatalogResult, rows [][]byte) error {
	if err := m.writeResult(session, result.columnPackets(), rows, m.status); err != nil {
		return err
	}
	if result.foundRows != nil {
		m.foundRows = *result.foundRows
	}
	return nil
}
