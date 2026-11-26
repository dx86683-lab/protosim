package protocols

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var mysqlSetVariables = regexp.MustCompile(`(?is)^SET\s+(.+)$`)
var mysqlVariableAssignment = regexp.MustCompile(`(?is)^(?:@@(?:(SESSION|LOCAL|GLOBAL)\.)?|(?:(SESSION|LOCAL|GLOBAL)\s+)?)(\w+)\s*=\s*(.+)$`)
var mysqlSupportedSQLModes = strings.Fields("ANSI_QUOTES ERROR_FOR_DIVISION_BY_ZERO NO_BACKSLASH_ESCAPES NO_ENGINE_SUBSTITUTION NO_ZERO_DATE ONLY_FULL_GROUP_BY STRICT_ALL_TABLES STRICT_TRANS_TABLES")

func (m *mysqlSimulation) storeSessionVariable(name, value string) {
	if m.sessionVariables == nil {
		m.sessionVariables = make(map[string]string)
	}
	m.sessionVariables[name] = value
}

func (m *mysqlSimulation) selectLimit() int64 {
	if value, ok := m.sessionVariables["sql_select_limit"]; ok {
		limit, _ := strconv.ParseInt(value, 10, 64)
		return limit
	}
	return 2147483647
}

func (m *mysqlSimulation) writeSetResult(session *SessionConnection, err error) error {
	if err != nil {
		return writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", err.Error()))
	}
	packet := mysqlOK(m.status)
	packet[1] = 1
	m.foundRows = 1
	return writeMySQLPacket(session, 1, packet)
}

func (m *mysqlSimulation) setSystemVariables(input string) error {
	assignments := mysqlSplitExpressions(input)
	if len(assignments) == 0 || len(assignments) > mysqlMaxProjections {
		return errors.New("query not supported by simulator")
	}
	for _, assignment := range assignments {
		match := mysqlVariableAssignment.FindStringSubmatch(assignment)
		if match == nil {
			return errors.New("query not supported by simulator")
		}
		global := strings.EqualFold(match[1], "GLOBAL") || strings.EqualFold(match[2], "GLOBAL")
		if err := m.setSystemVariable(strings.ToLower(match[3]), strings.TrimSpace(match[4]), global); err != nil {
			return err
		}
	}
	return nil
}

func (m *mysqlSimulation) setSystemVariable(name, input string, global bool) error {
	_, exists := mysqlDefaultVariableValues[name]
	if !exists {
		return fmt.Errorf("Unknown system variable '%s'", name)
	}
	quoted := len(input) >= 2 && (input[0] == '\'' || input[0] == '"') && input[len(input)-1] == input[0]
	useDefault := !quoted && strings.EqualFold(input, "DEFAULT")
	value := input
	if quoted {
		value = mysqlUnquoteProjection(input)
	} else if useDefault {
		value = mysqlGlobalVariableValue(name)
	} else if strings.EqualFold(value, "NULL") {
		value = "<nil>"
	}
	invalid := func() error { return fmt.Errorf("Variable '%s' can't be set to the value of '%s'", name, value) }
	switch name {
	case "autocommit":
		switch {
		case strings.EqualFold(value, "ON"), !quoted && (value == "1" || strings.EqualFold(value, "TRUE")):
			value = "1"
		case strings.EqualFold(value, "OFF"), !quoted && (value == "0" || strings.EqualFold(value, "FALSE")):
			value = "0"
		default:
			return invalid()
		}
		if !global {
			m.autocommitOff = value == "0"
			m.status = !m.autocommitOff
			return nil
		}
	case "wait_timeout", "max_allowed_packet", "sql_select_limit":
		n, err := strconv.ParseInt(value, 10, 64)
		if quoted || err != nil || name == "wait_timeout" && (n < 1 || n > 31536000) ||
			name == "max_allowed_packet" && (n < 1024 || n > 1073741824) {
			return invalid()
		}
		value = strconv.FormatInt(n, 10)
	case "group_concat_max_len":
		n, err := strconv.ParseUint(strings.TrimPrefix(value, "+"), 10, 64)
		if strings.HasPrefix(value, "-") {
			var signed int64
			signed, err = strconv.ParseInt(value, 10, 64)
			n = uint64(signed)
		}
		if quoted || err != nil || n < 4 {
			return invalid()
		}
		value = strconv.FormatUint(n, 10)
	case "sql_mode":
		if value != "" {
			modes := strings.Split(strings.ToUpper(value), ",")
			for _, mode := range modes {
				if !slices.Contains(mysqlSupportedSQLModes, mode) {
					return fmt.Errorf("value %s was not found in the set", mode)
				}
			}
			slices.Sort(modes)
			value = strings.Join(slices.Compact(modes), ",")
		}
	case "time_zone", "character_set_client", "character_set_connection", "character_set_results":
		if value == "<nil>" && !quoted {
			if name != "character_set_results" {
				return invalid()
			}
			value = ""
		}
	default:
		return errors.New("query not supported by simulator")
	}
	if global {
		if !useDefault {
			mysqlGlobalVariables.Lock()
			mysqlGlobalVariables.values[name] = value
			mysqlGlobalVariables.Unlock()
		}
	} else {
		m.storeSessionVariable(name, value)
	}
	return nil
}
