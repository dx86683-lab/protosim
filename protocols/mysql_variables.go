package protocols

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const mysqlVariableToken = `@@(?:(?:GLOBAL|SESSION)\.)?(?:[\w.]+|` + "`(?:[^`]|``)*`" + `)`

var mysqlShowVariables = regexp.MustCompile(`(?i)^SHOW\s+(?:(?:GLOBAL|SESSION)\s+)?VARIABLES(?:\s+LIKE\s+('(?:[^']|'')*'|"(?:[^"]|"")*"))?$`)
var mysqlShowVariablesWhere = regexp.MustCompile(`(?i)^SHOW\s+(?:(?:GLOBAL|SESSION)\s+)?VARIABLES\s+WHERE\s+(\w)`)
var mysqlVariableColumns = []mysqlColumn{{"Variable_name", 0xfc}, {"Value", 0xfc}}

//go:embed fixtures/mysql-system-variables.json
var mysqlVariableData []byte

type mysqlSystemVariable struct {
	Value string
	Show  *string
	Kind  byte
	Flags byte
	Error string
}

type mysqlSystemVariableError string

func (e mysqlSystemVariableError) Error() string { return string(e) }

type mysqlVariableReference struct {
	name   string
	global bool
}

var mysqlDefaultVariableValues, mysqlSystemVariableNames = func() (map[string]mysqlSystemVariable, []string) {
	var values map[string]mysqlSystemVariable
	if err := json.Unmarshal(mysqlVariableData, &values); err != nil {
		panic(err)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	return values, names
}()

// The simulated globals are shared across MySQL listeners in the process.
var mysqlGlobalVariables = struct {
	sync.RWMutex
	values map[string]string
}{values: make(map[string]string)}

func mysqlGlobalVariableValue(name string) string {
	mysqlGlobalVariables.RLock()
	value, ok := mysqlGlobalVariables.values[name]
	mysqlGlobalVariables.RUnlock()
	if ok {
		return value
	}
	return mysqlDefaultVariableValues[name].Value
}

func mysqlGlobalVariableSnapshot() map[string]string {
	mysqlGlobalVariables.RLock()
	defer mysqlGlobalVariables.RUnlock()
	return maps.Clone(mysqlGlobalVariables.values)
}

func (m *mysqlSimulation) sessionVariableValue(name, fallback string) string {
	if name == "autocommit" {
		if m.autocommitOff {
			return "0"
		}
		return "1"
	}
	if value, ok := m.sessionVariables[name]; ok {
		return value
	}
	return fallback
}

func mysqlSystemVariableProjection(token, alias string) (mysqlExpression, error) {
	name, scope := token[2:], "SESSION"
	if prefix, rest, ok := strings.Cut(name, "."); ok {
		switch strings.ToUpper(prefix) {
		case "GLOBAL":
			name, scope = rest, "GLOBAL"
		case "SESSION":
			name = rest
		}
	}
	key := strings.ToLower(name)
	variable := mysqlDefaultVariableValues[key]
	if variable.Kind == 0 {
		return mysqlExpression{}, mysqlSystemVariableError(fmt.Sprintf("Unknown system variable '%s'", name))
	}
	label := mysqlUnquoteProjection(alias)
	if label == "" {
		label = "@@" + scope + "." + key
	}
	return mysqlExpression{
		column:   mysqlColumn{label, variable.Kind},
		flags:    variable.Flags,
		variable: &mysqlVariableReference{name: key, global: scope == "GLOBAL"},
	}, nil
}

func (m *mysqlSimulation) systemVariableValue(ref *mysqlVariableReference) (string, error) {
	variable := mysqlDefaultVariableValues[ref.name]
	if variable.Error != "" {
		return "", mysqlSystemVariableError(variable.Error)
	}
	if ref.global {
		return mysqlGlobalVariableValue(ref.name), nil
	}
	return m.sessionVariableValue(ref.name, variable.Value), nil
}

func (m *mysqlSimulation) binarySystemVariable(expr mysqlExpression) ([]byte, error) {
	value, err := m.systemVariableValue(expr.variable)
	if err != nil {
		return nil, err
	}
	return mysqlSystemVariableBinaryValue(expr, value)
}

func mysqlSystemVariableBinaryValue(expr mysqlExpression, value string) ([]byte, error) {
	switch expr.column.kind {
	case 0xfd:
		return appendMySQLString(nil, value), nil
	case 1:
		value, err := strconv.ParseInt(value, 10, 8)
		if err == nil {
			return []byte{byte(value)}, nil
		}
	case 5:
		value, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return binary.LittleEndian.AppendUint64(nil, math.Float64bits(value)), nil
		}
	case 8:
		if expr.flags&0x20 != 0 {
			value, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				return binary.LittleEndian.AppendUint64(nil, value), nil
			}
		} else {
			value, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				return binary.LittleEndian.AppendUint64(nil, uint64(value)), nil
			}
		}
	}
	return nil, mysqlSystemVariableError("invalid system variable value: " + expr.variable.name)
}

func (m *mysqlSimulation) showSystemVariables(session *SessionConnection, filter string, previousStatus bool) error {
	rows, err := m.systemVariableRows(filter)
	if err != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "query not supported by simulator"))
	}
	if filter == "" {
		// Unfiltered SHOW sends column metadata before applying the query status.
		return m.writeRowsWithMetadataStatus(session, mysqlVariableColumns, rows, previousStatus)
	}
	return m.writeRows(session, mysqlVariableColumns, rows)
}

func (m *mysqlSimulation) systemVariableRows(filter string) ([][]string, error) {
	var pattern *regexp.Regexp
	if filter != "" {
		var err error
		pattern, err = mysqlLikePattern(mysqlUnquoteProjection(filter))
		if err != nil {
			return nil, err
		}
	}
	var rows [][]string
	for _, name := range mysqlSystemVariableNames {
		if pattern != nil && !pattern.MatchString(name) {
			continue
		}
		variable := mysqlDefaultVariableValues[name]
		value := variable.Value
		if variable.Show != nil {
			value = *variable.Show
		}
		// The reference displays session overrides even with SHOW GLOBAL.
		rows = append(rows, []string{name, m.sessionVariableValue(name, value)})
	}
	return rows, nil
}

func mysqlLikePattern(filter string) (*regexp.Regexp, error) {
	var pattern strings.Builder
	pattern.WriteString(`(?is)^`)
	escaped := false
	for _, char := range filter {
		switch {
		case escaped:
			pattern.WriteString(regexp.QuoteMeta(string(char)))
			escaped = false
		case char == '\\':
			escaped = true
		case char == '%':
			pattern.WriteString(`.*`)
		case char == '_':
			pattern.WriteByte('.')
		default:
			pattern.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	if escaped {
		pattern.WriteString(`\\`)
	}
	pattern.WriteByte('$')
	return regexp.Compile(pattern.String())
}
