package protocols

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var mysqlDiagnosticToken = regexp.MustCompile(`(?is)` + mysqlCatalogProjectionString + `|` +
	mysqlMetadataName + `|<=>|<=|>=|<>|!=|[^\s]`)
var mysqlDiagnosticExprToken = regexp.MustCompile(`(?is)^(` + mysqlCatalogProjectionString + `|` +
	mysqlProjectionNumber + `|` + mysqlCatalogField + `|<=>|<=|>=|<>|!=|[=<>?])`)

func mysqlDiagnosticClause(raw string) bool {
	switch strings.ToUpper(raw) {
	case "AS", "ON", "USING", "WHERE", "ORDER", "LIMIT", "GROUP", "HAVING", "UNION", "JOIN":
		return true
	}
	return false
}

func mysqlDiagnosticIdentifier(raw string) string {
	name := mysqlUnquoteProjection(raw)
	if mysqlDiagnosticClause(name) {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	switch strings.ToUpper(name) {
	case "TABLES", "COLUMNS", "ENGINES", "PLUGINS", "SCHEMA_NAME", "FIRST":
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	if strings.ContainsAny(name, " `\t\n\r") {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	return name
}

func mysqlDiagnosticAt(sql string, offset int, message, fallback string) *mysqlMetadataError {
	token := mysqlDiagnosticToken.FindStringIndex(sql[offset:])
	if token == nil {
		return &mysqlMetadataError{1105, fmt.Sprintf("%s at position %d near '%s'", message, len(sql)+1, fallback)}
	}
	raw := sql[offset+token[0] : offset+token[1]]
	return &mysqlMetadataError{1105, fmt.Sprintf("%s at position %d near '%s'", message, offset+token[1]+1, mysqlUnquoteProjection(raw))}
}

func mysqlCatalogDerivedDiagnostic(sql string, item mysqlCatalogFromItem, base int, inner, rest string) *mysqlMetadataError {
	offset := base + item.offset + len(strings.TrimRightFunc(item.raw, unicode.IsSpace)) - len(rest)
	tokens := mysqlDiagnosticToken.FindAllStringIndex(rest, -1)
	if len(tokens) == 0 || mysqlDiagnosticClause(rest[tokens[0][0]:tokens[0][1]]) &&
		!strings.EqualFold(rest[tokens[0][0]:tokens[0][1]], "AS") {
		last := ""
		for _, token := range mysqlDiagnosticToken.FindAllString(inner, -1) {
			if token != ")" && token != "(" && token != "," {
				last = mysqlUnquoteProjection(token)
			}
		}
		return mysqlDiagnosticAt(sql, offset, "Every derived table must have its own alias", last)
	}
	if len(tokens) == 1 && strings.EqualFold(rest[tokens[0][0]:tokens[0][1]], "AS") {
		return mysqlDiagnosticAt(sql, offset, "syntax error", "")
	}
	alias := 0
	if strings.EqualFold(rest[tokens[0][0]:tokens[0][1]], "AS") {
		alias++
	}
	if len(tokens) > alias+2 && rest[tokens[alias+1][0]:tokens[alias+1][1]] == "(" {
		for _, token := range tokens[alias+2:] {
			raw := rest[token[0]:token[1]]
			if raw == ")" {
				break
			}
			if strings.EqualFold(raw, "FIRST") {
				return mysqlDiagnosticAt(sql, offset+token[0], "syntax error", "")
			}
		}
	}
	return mysqlCatalogUnsupported()
}

func mysqlCatalogGroupedDiagnostic(sql string, item mysqlCatalogFromItem, base int, rest string) *mysqlMetadataError {
	offset := base + item.offset + len(strings.TrimRightFunc(item.raw, unicode.IsSpace)) - len(rest)
	if token := mysqlDiagnosticToken.FindString(rest); token != "" &&
		!strings.EqualFold(token, "ON") && !strings.EqualFold(token, "USING") {
		return mysqlDiagnosticAt(sql, offset, "syntax error", "")
	}
	inner, _, _ := mysqlCatalogSplitGroup(item.raw)
	text, ok := mysqlDiagnosticSources(inner, 0)
	if !ok {
		return mysqlCatalogUnsupported()
	}
	return &mysqlMetadataError{1105, "unsupported syntax: (" + text + ")"}
}

func mysqlDiagnosticSources(raw string, depth int) (string, bool) {
	if depth >= mysqlMaxCatalogueDepth {
		return "", false
	}
	items, end, balanced := mysqlCatalogScanSources(raw)
	if !balanced || end != len(raw) {
		return "", false
	}
	var formatted strings.Builder
	for i, item := range items {
		if i != 0 {
			join := strings.ToLower(strings.Join(strings.Fields(item.kind), " "))
			switch join {
			case ",":
				formatted.WriteString(", ")
			case "inner join", "cross join":
				formatted.WriteString(" join ")
			default:
				formatted.WriteString(" " + strings.ReplaceAll(join, " outer", "") + " ")
			}
		}
		if inner, rest, ok := mysqlCatalogSplitGroup(item.raw); ok && strings.TrimSpace(rest) == "" {
			name, ok := mysqlDiagnosticSources(inner, depth+1)
			if !ok {
				return "", false
			}
			formatted.WriteString("(" + name + ")")
			continue
		}
		match := mysqlCatalogChainSource.FindStringSubmatch(item.raw)
		if match == nil {
			return "", false
		}
		name := mysqlDiagnosticIdentifier(match[1])
		if match[2] != "" {
			name += "." + mysqlDiagnosticIdentifier(match[2])
		}
		if match[3] != "" {
			name += " as " + mysqlDiagnosticIdentifier(match[3])
		}
		formatted.WriteString(name)
		switch strings.ToUpper(match[4]) {
		case "ON":
			expr, ok := mysqlDiagnosticExpression(match[5])
			if !ok {
				return "", false
			}
			formatted.WriteString(" on " + expr)
		case "USING":
			inner, rest, ok := mysqlCatalogSplitGroup(match[5])
			if !ok || strings.TrimSpace(rest) != "" {
				return "", false
			}
			names := mysqlSplitExpressions(inner)
			for i, column := range names {
				names[i] = mysqlDiagnosticIdentifier(column)
			}
			formatted.WriteString(" using (" + strings.Join(names, ", ") + ")")
		}
	}
	return formatted.String(), true
}

func mysqlDiagnosticExpression(raw string) (string, bool) {
	var parts []string
	for raw = strings.TrimSpace(raw); raw != ""; raw = strings.TrimSpace(raw) {
		token := mysqlDiagnosticExprToken.FindString(raw)
		if token == "" {
			return "", false
		}
		raw = raw[len(token):]
		switch strings.ToUpper(token) {
		case "AND", "OR", "NOT", "LIKE", "IS", "NULL", "TRUE", "FALSE":
			token = strings.ToLower(token)
		default:
			if field := mysqlCatalogObject.FindStringSubmatch(token); field != nil {
				token = mysqlDiagnosticIdentifier(field[1])
				if field[2] != "" {
					token += "." + mysqlDiagnosticIdentifier(field[2])
				}
			}
		}
		parts = append(parts, token)
	}
	return strings.Join(parts, " "), len(parts) != 0
}

func mysqlDiagnosticSelect(query string) (string, bool) {
	prefix := mysqlCatalogChainPrefix.FindStringSubmatch(query)
	if prefix == nil {
		return "", false
	}
	body := query[len(prefix[0]):]
	_, end, balanced := mysqlCatalogScanSources(body)
	if !balanced {
		return "", false
	}
	sources, ok := mysqlDiagnosticSources(strings.TrimSpace(body[:end]), 0)
	if !ok {
		return "", false
	}
	tail := mysqlCatalogJoinTail(body[end:])
	if tail == nil || tail[1] != "" || tail[2] != "" || tail[3] != "" || tail[4] != "" {
		return "", false
	}
	projections := mysqlSplitExpressions(prefix[2])
	if len(projections) == 0 {
		return "", false
	}
	for i, field := range projections {
		expr, ok := mysqlDiagnosticExpression(field)
		if !ok {
			return "", false
		}
		projections[i] = expr
	}
	text := "select "
	if prefix[1] != "" {
		text += "distinct "
	}
	text += strings.Join(projections, ", ") + " from " + sources
	if tail[0] != "" {
		where, ok := mysqlDiagnosticExpression(tail[0])
		if !ok {
			return "", false
		}
		text += " where " + where
	}
	return text, true
}
