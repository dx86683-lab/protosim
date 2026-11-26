package protocols

import (
	"regexp"
	"strings"
)

const mysqlCatalogProjectionString = `(?:'(?:[^']|'')*'|"(?:[^"]|"")*")`

var mysqlCatalogScalar = regexp.MustCompile(`(?i)^(\?|NULL|TRUE|FALSE|` + mysqlCatalogProjectionString +
	`|` + mysqlProjectionNumber + `|` + mysqlVariableToken + `|` + mysqlCatalogueFunction + `|` +
	mysqlCatalogueBareFunction + `)(?:\s+(?:AS\s+)?(` +
	mysqlMetadataName + `|` + mysqlCatalogProjectionString + `))?$`)

// Projection parameters precede ON, WHERE and LIMIT on the wire. Reserve them
// before resolving those clauses, which retain their existing error order.
func reserveMySQLProjectionBindings(projection string, bindings *mysqlCatalogBindings) *mysqlCatalogBindings {
	if bindings == nil || !strings.Contains(projection, "?") {
		return nil
	}
	projectionBindings := *bindings
	for _, expression := range mysqlSplitExpressions(projection) {
		if bindings.unbound {
			expression = mysqlCatalogUngroupProjection(expression)
		}
		if match := mysqlCatalogScalar.FindStringSubmatch(expression); match != nil && match[1] == "?" {
			bindings.next++
		} else if aggregate := mysqlCatalogAggregateExpression.FindStringSubmatch(expression); aggregate != nil &&
			strings.TrimSpace(aggregate[4]) == "?" {
			bindings.next++
		} else if concat := mysqlGroupConcatExpression.FindStringSubmatch(expression); concat != nil {
			for _, token := range mysqlGroupConcatParams.FindAllString(concat[4], -1) {
				if token == "?" {
					bindings.next++
				}
			}
		}
	}
	return &projectionBindings
}

func mysqlCatalogUngroupProjection(raw string) string {
	if inner, alias, grouped := mysqlCatalogSplitGroup(raw); grouped {
		return inner + alias
	}
	return raw
}

func (m *mysqlSimulation) catalogScalarProjection(raw string, bindings *mysqlCatalogBindings) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	var field mysqlCatalogProjectionField
	match := mysqlCatalogScalar.FindStringSubmatch(raw)
	if match == nil {
		return field, nil
	}
	value := match[1]
	label := mysqlUnquoteProjection(match[2])
	if match[2] == "" {
		label = value
		if value[0] == '\'' || value[0] == '"' {
			label = value[1 : len(value)-1]
		}
	}
	expr := mysqlExpression{column: mysqlColumn{label, 0xfc}, charset: 33}
	switch {
	case value == "?":
		if bindings == nil {
			return field, &mysqlMetadataError{1105, "unbound variable \"v1\" in query"}
		}
		position := bindings.next
		text, present, failure := bindings.operand(value, m.current)
		switch {
		case failure != nil && bindings.unbound && bindings.next > position:
			expr.contextError = failure.message
		case failure != nil:
			return field, failure
		case !bindings.preparing:
			bound := bindings.values[position]
			expr.text, expr.value, expr.column.kind = text, bound.data, bound.kind
			if !present {
				expr.flags = 0x80
			} else if bound.binary {
				expr.charset, expr.flags = 63, 0x80
			}
		}
	case value[0] == '\'' || value[0] == '"':
		expr.text = mysqlUnquoteProjection(value)
		expr.value = appendMySQLString(nil, expr.text)
	case strings.HasPrefix(value, "@@"):
		var err error
		expr, err = mysqlSystemVariableProjection(value, match[2])
		if err != nil {
			return field, &mysqlMetadataError{1105, err.Error()}
		}
		expr.charset = 33
		label = expr.column.name
		if bindings == nil || !bindings.preparing {
			expr.text, err = m.systemVariableValue(expr.variable)
			if err == nil {
				expr.value, err = mysqlSystemVariableBinaryValue(expr, expr.text)
			}
			if err != nil {
				return field, &mysqlMetadataError{1105, err.Error()}
			}
		}
	case strings.HasSuffix(value, ")") || strings.HasPrefix(strings.ToUpper(value), "CURRENT_"):
		if failure := m.catalogueFunction(&expr, value); failure != nil {
			return field, failure
		}
	default:
		literal, err := mysqlProjection(value, "", "")
		if err != nil {
			return field, mysqlCatalogUnsupported()
		}
		expr.text, expr.value, expr.column.kind, expr.flags = literal.text, literal.value, literal.column.kind, literal.flags
	}
	return mysqlCatalogProjectionField{
		label: label, kind: expr.column.kind, charset: expr.charset, flags: expr.flags, scalar: &expr,
	}, nil
}
