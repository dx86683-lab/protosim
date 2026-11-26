package protocols

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const mysqlGroupConcatQuoted = mysqlCatalogProjectionString + "|`(?:[^`]|``)*`"
const mysqlGroupConcatItem = "(?:" + mysqlGroupConcatQuoted + "|[^'\"`()])"
const mysqlGroupConcatToken = `GROUP_CONCAT\s*\(` + mysqlGroupConcatItem + `*\)`

var mysqlGroupConcatExpression = regexp.MustCompile(`(?is)^((GROUP_CONCAT)\s*\(\s*(?:(DISTINCT)\s+)?(` + mysqlGroupConcatItem + `*)\))(?:\s+(?:AS\s+)?(` + mysqlMetadataName + "|" + mysqlCatalogProjectionString + `))?$`)
var mysqlGroupConcatParts = regexp.MustCompile(`(?is)^(` + mysqlGroupConcatItem + `+?)(?:\s+ORDER\s+BY\s+(` +
	mysqlGroupConcatItem + `+?))?(?:\s+SEPARATOR\s+(` + mysqlCatalogProjectionString + `))?\s*$`)
var mysqlGroupConcatOrder = regexp.MustCompile(`(?is)^(.+?)(?:\s+(ASC|DESC))?$`)
var mysqlGroupConcatParams = regexp.MustCompile(mysqlGroupConcatQuoted + `|\?`)
var mysqlGroupConcatQuery = regexp.MustCompile(`(?is)` + mysqlGroupConcatQuoted + `|\bGROUP_CONCAT\s*\((` + mysqlGroupConcatItem + `*)\)`)
var mysqlGroupConcatInvalid = regexp.MustCompile(`(?is)` + mysqlGroupConcatQuoted + `|\b(LIMIT)\b|\bSEPARATOR\s+(\?|\w+\b)`)
var mysqlGroupConcatLiteral = regexp.MustCompile(`^` + mysqlCatalogProjectionString + `$`)

type mysqlGroupConcat struct {
	value     mysqlWhereValue
	order     []mysqlGroupConcatOrderField
	parser    *mysqlWhereParser
	separator string
	limit     uint64
}

type mysqlGroupConcatOrderField struct {
	value mysqlWhereValue
	desc  bool
}

func mysqlCatalogParseAggregate(raw string) []string {
	if match := mysqlCatalogAggregateExpression.FindStringSubmatch(raw); match != nil {
		return match
	}
	return mysqlGroupConcatExpression.FindStringSubmatch(raw)
}

func mysqlGroupConcatSyntax(query string) *mysqlMetadataError {
	if !strings.Contains(strings.ToUpper(query), "GROUP_CONCAT") {
		return nil
	}
	params := 0
	previous := 0
	for _, match := range mysqlGroupConcatQuery.FindAllStringSubmatchIndex(query, -1) {
		if match[2] < 0 {
			continue
		}
		for _, token := range mysqlGroupConcatParams.FindAllString(query[previous:match[2]], -1) {
			if token == "?" {
				params++
			}
		}
		previous = match[2]
		body := query[match[2]:match[3]]
		if strings.TrimSpace(body) == "" {
			name := strings.TrimSpace(query[match[0] : match[2]-1])
			return &mysqlMetadataError{1105, fmt.Sprintf("syntax error at position %d near '%s'", match[1]+1, name)}
		}
		for _, token := range mysqlGroupConcatInvalid.FindAllStringSubmatchIndex(body, -1) {
			if token[2] >= 0 {
				return mysqlDiagnosticAt(query, match[2]+token[2], "syntax error", "")
			}
			if token[4] >= 0 {
				if body[token[4]:token[5]] != "?" {
					return mysqlDiagnosticAt(query, match[2]+token[4], "syntax error", "")
				}
				for _, v := range mysqlGroupConcatParams.FindAllString(body[:token[4]], -1) {
					if v == "?" {
						params++
					}
				}
				name := ":v" + strconv.Itoa(params+1)
				return &mysqlMetadataError{1105, fmt.Sprintf("syntax error at position %d near '%s'",
					match[2]+token[5]+1, name)}
			}
		}
	}
	return nil
}

func mysqlGroupConcatDisplay(match []string) string {
	distinct := ""
	if match[3] != "" {
		distinct = "DISTINCT "
	}
	return "group_concat(" + distinct + strings.TrimSpace(match[4]) + ")"
}

func (m *mysqlSimulation) catalogGroupConcat(match []string, source mysqlCatalogSource, bindings *mysqlCatalogBindings) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	var field mysqlCatalogProjectionField
	parts := mysqlGroupConcatParts.FindStringSubmatch(strings.TrimSpace(match[4]))
	if parts == nil {
		return field, mysqlCatalogUnsupported()
	}
	args := mysqlSplitExpressions(parts[1])
	if len(args) == 0 || len(args) > mysqlMaxProjections {
		return field, mysqlCatalogUnsupported()
	}
	parser := &mysqlWhereParser{model: m, mysqlCatalogueJoinParser: mysqlCatalogueJoinParser{
		source: source, bindings: bindings, database: m.current,
	}}
	key := match[1]
	if bindings != nil && strings.Contains(match[4], "?") {
		key += "#" + strconv.Itoa(bindings.next)
	}
	limit, _ := strconv.ParseUint(m.sessionVariableValue("group_concat_max_len", mysqlDefaultVariableValues["group_concat_max_len"].Value), 10, 64)
	group := &mysqlGroupConcat{parser: parser, separator: ",", limit: limit}
	label := match[1]
	if match[5] != "" {
		label = mysqlUnquoteProjection(match[5])
	}
	if parts[3] != "" {
		if separator := mysqlGroupConcatString(parts[3]); separator != "" {
			group.separator = separator
		}
	}
	for i, arg := range args {
		if arg == "*" {
			return field, &mysqlMetadataError{1105, "plan is not resolved because of node '*plan.GroupBy'"}
		}
		value, failure := mysqlGroupConcatValue(parser, arg)
		if failure != nil {
			return field, failure
		}
		if i == 0 {
			group.value = value
		}
	}
	if parts[2] != "" {
		for _, expression := range mysqlSplitExpressions(parts[2]) {
			order := mysqlGroupConcatOrder.FindStringSubmatch(expression)
			if order == nil {
				return field, mysqlCatalogUnsupported()
			}
			value, failure := mysqlGroupConcatValue(parser, order[1])
			if failure != nil {
				return field, failure
			}
			group.order = append(group.order, mysqlGroupConcatOrderField{value, strings.EqualFold(order[2], "DESC")})
		}
	}
	if match[5] == "" && match[3] == "" && len(args) == 1 && parts[2] == "" && parts[3] == "" &&
		match[1] == "group_concat("+args[0]+")" {
		name := args[0]
		if mysqlCatalogObject.MatchString(name) {
			if column, failure := source.resolve(name); failure == nil && column.source != "" {
				qualifier := column.qualifier
				if qualifier == "" {
					qualifier = source.baseName
				}
				if qualifier != "" {
					label = "group_concat(" + strings.ToLower(qualifier+"."+column.source) + ")"
				}
			}
		}
	}
	aggregate := &mysqlCatalogAggregate{key: key, method: "group_concat", distinct: match[3] != "", concat: group}
	kind := byte(0xfc)
	if limit <= 512 {
		kind = 0xfd
	}
	return mysqlCatalogProjectionField{label: label, kind: kind, charset: 33, aggregate: aggregate}, nil
}

func mysqlGroupConcatValue(parser *mysqlWhereParser, raw string) (mysqlWhereValue, *mysqlMetadataError) {
	if mysqlGroupConcatLiteral.MatchString(raw) {
		text := mysqlGroupConcatString(raw)
		return mysqlWhereValue{value: func(mysqlCatalogRecord) (string, bool) { return text, true }}, nil
	}
	if strings.EqualFold(raw, "true") || strings.EqualFold(raw, "false") {
		return mysqlWhereValue{value: func(mysqlCatalogRecord) (string, bool) { return strings.ToLower(raw), true }}, nil
	}
	parser.rest = raw
	expression, failure := parser.scalar(1)
	if failure == nil && strings.TrimSpace(parser.rest) != "" {
		failure = mysqlCatalogUnsupported()
	}
	return expression, failure
}

func mysqlGroupConcatString(raw string) string {
	text := mysqlUnquoteProjection(raw)
	if !strings.ContainsRune(text, '\\') {
		return text
	}
	var decoded strings.Builder
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '\\' && i+1 < len(text) {
			i++
			ch = text[i]
			switch ch {
			case '0':
				ch = 0
			case 'b':
				ch = '\b'
			case 'n':
				ch = '\n'
			case 'r':
				ch = '\r'
			case 't':
				ch = '\t'
			case 'Z':
				ch = 26
			}
		}
		decoded.WriteByte(ch)
	}
	return decoded.String()
}

func (g *mysqlGroupConcat) evaluate(rows []mysqlCatalogRecord, distinct bool) (string, bool, *mysqlMetadataError) {
	type item struct {
		row  mysqlCatalogRecord
		text string
	}
	var values []item
	var seen map[string]struct{}
	if distinct {
		seen = make(map[string]struct{})
	}
	for _, row := range rows {
		value, present := g.value.value(row)
		if !present {
			continue
		}
		if distinct {
			if _, duplicate := seen[value]; duplicate {
				continue
			}
			seen[value] = struct{}{}
		}
		values = append(values, item{row, value})
	}
	if len(g.order) != 0 {
		slices.SortStableFunc(values, func(a, b item) int { return g.compareRows(a.row, b.row) })
	}
	var output strings.Builder
	for i, value := range values {
		if i > 0 {
			mysqlWriteGroupConcat(&output, g.separator, g.limit)
		}
		mysqlWriteGroupConcat(&output, value.text, g.limit)
		if uint64(output.Len()) == g.limit {
			break
		}
	}
	return output.String(), len(values) > 0, g.parser.failure
}

func mysqlWriteGroupConcat(output *strings.Builder, text string, limit uint64) {
	remaining := limit - uint64(output.Len())
	output.WriteString(text[:min(remaining, uint64(len(text)))])
}

func (g *mysqlGroupConcat) compareRows(left, right mysqlCatalogRecord) int {
	for _, order := range g.order {
		a, aOK := order.value.value(left)
		b, bOK := order.value.value(right)
		result := strings.Compare(a, b)
		switch {
		case aOK && !bOK:
			result = 1
		case !aOK && bOK:
			result = -1
		case aOK && order.value.numeric:
			if numeric, valid := mysqlCatalogueNumericOrder(a, b); valid {
				result = numeric
			}
		}
		if result != 0 {
			if order.desc {
				return -result
			}
			return result
		}
	}
	return 0
}
