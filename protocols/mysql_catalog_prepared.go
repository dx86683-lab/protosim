package protocols

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type mysqlCatalogBindings struct {
	preparing bool
	unbound   bool
	values    []mysqlBoundParameter
	types     []mysqlParameter
	next      int
}

func (b *mysqlCatalogBindings) operand(raw, database string) (string, bool, *mysqlMetadataError) {
	if raw != "?" {
		if strings.HasPrefix(strings.ToUpper(raw), "DATABASE") {
			return database, database != "", nil
		}
		return strings.ReplaceAll(mysqlUnquoteProjection(raw), `\\`, `\`), true, nil
	}
	if b == nil || b.next >= mysqlMaxProjections {
		return "", false, mysqlCatalogUnsupported()
	}
	position := b.next
	b.next++
	if b.preparing {
		// A placeholder's value does not affect projected column metadata.
		return "0", true, nil
	}
	if b.unbound {
		return "", false, mysqlCatalogUnboundVariable(position)
	}
	if position >= len(b.values) {
		return "", false, &mysqlMetadataError{1210, errMySQLExecuteArgs.Error()}
	}
	value := b.values[position]
	switch value.kind {
	case 6:
		return "", false, nil
	case 8:
		bits := binary.LittleEndian.Uint64(value.data)
		if b.types[position].flags&0x80 != 0 {
			return strconv.FormatUint(bits, 10), true, nil
		}
		return strconv.FormatInt(int64(bits), 10), true, nil
	case 5:
		bits := binary.LittleEndian.Uint64(value.data)
		return strconv.FormatFloat(math.Float64frombits(bits), 'f', -1, 64), true, nil
	default:
		text, width := mysqlLengthEncodedParameter(value.data)
		if width != 0 {
			return string(text), true, nil
		}
	}
	return "", false, &mysqlMetadataError{1210, errMySQLExecuteArgs.Error()}
}

func mysqlCatalogUnboundVariable(position int) *mysqlMetadataError {
	return &mysqlMetadataError{1105, fmt.Sprintf("unbound variable \"v%d\" in query", position+1)}
}

func (b *mysqlCatalogBindings) limit(raw, database string, fallback uint64) (uint64, *mysqlMetadataError) {
	if raw == "" {
		return fallback, nil
	}
	value, present, failure := b.operand(raw, database)
	if failure != nil {
		return 0, failure
	}
	count, err := strconv.ParseUint(value, 10, 64)
	if err != nil || !present {
		return 0, &mysqlMetadataError{1105, "Invalid syntax: invalid limit"}
	}
	return count, nil
}

func (r *mysqlCatalogResult) columnPackets() [][]byte {
	columns := make([][]byte, 0, len(r.columns))
	for _, field := range r.columns {
		columns = append(columns, mysqlColumnPacket(mysqlColumn{field.label, field.kind}, field.charset, field.flags))
	}
	return columns
}

func (r *mysqlCatalogResult) binaryRows() ([][]byte, error) {
	rows := make([][]byte, 0, len(r.rows))
	for _, text := range r.rows {
		row := make([]byte, 1+(len(r.columns)+9)/8)
		for index, field := range r.columns {
			if len(text) == 0 {
				return nil, errMySQLExecuteArgs
			}
			if text[0] == 0xfb {
				row[1+(index+2)/8] |= 1 << ((index + 2) % 8)
				text = text[1:]
				continue
			}
			value, width := mysqlLengthEncodedParameter(text)
			if width == 0 {
				return nil, errMySQLExecuteArgs
			}
			if field.scalar != nil {
				row = append(row, field.scalar.value...)
				text = text[width:]
				continue
			}
			switch field.kind {
			case 1, 2, 3, 8:
				var number uint64
				var err error
				if field.flags&0x20 != 0 {
					number, err = strconv.ParseUint(string(value), 10, 64)
				} else {
					var signed int64
					signed, err = strconv.ParseInt(string(value), 10, 64)
					number = uint64(signed)
				}
				if err != nil {
					return nil, err
				}
				switch field.kind {
				case 1:
					row = append(row, byte(number))
				case 2:
					row = binary.LittleEndian.AppendUint16(row, uint16(number))
				case 3:
					row = binary.LittleEndian.AppendUint32(row, uint32(number))
				case 8:
					row = binary.LittleEndian.AppendUint64(row, number)
				}
			case 5:
				number, err := strconv.ParseFloat(string(value), 64)
				if err != nil {
					return nil, err
				}
				row = binary.LittleEndian.AppendUint64(row, math.Float64bits(number))
			case 7, 12:
				stamp, err := time.Parse("2006-01-02 15:04:05", string(value))
				if err != nil {
					return nil, err
				}
				row = appendMySQLCatalogueDateTime(row, stamp)
			default:
				row = append(row, text[:width]...)
			}
			text = text[width:]
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (m *mysqlSimulation) executeCatalog(session *SessionConnection, stmt *mysqlStatement, input []byte) error {
	values, err := stmt.bind(input)
	if err != nil {
		code := uint16(2027)
		if err == errMySQLExecuteArgs {
			code = 1210
		}
		return writeMySQLPacket(session, 1, mysqlErrorPacket(code, "HY000", err.Error()))
	}
	if m.selectLimit() < 0 {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "Invalid syntax: negative limit"))
	}
	result, failure := m.catalogSelect(stmt.catalogSQL, &mysqlCatalogBindings{values: values, types: stmt.parameters})
	if failure != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(failure.code, "HY000", failure.message))
	}
	if result == nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "query not supported by simulator"))
	}
	rows, err := result.binaryRows()
	if err != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", err.Error()))
	}
	m.status = !m.autocommitOff
	return m.writeCatalogueResult(session, result, rows)
}
