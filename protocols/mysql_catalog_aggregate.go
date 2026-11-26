package protocols

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const mysqlCatalogAggregateName = `(?:COUNT|MIN|MAX|SUM|AVG)`
const mysqlCatalogAggregateArg = `(?:\*|\?|NULL\b|` + mysqlProjectionNumber + "|" + mysqlCatalogProjectionString + "|" + mysqlCatalogField + `)`
const mysqlCatalogAggregateArgs = mysqlCatalogAggregateArg + `(?:\s*,\s*` + mysqlCatalogAggregateArg + `)*`
const mysqlCatalogAggregateToken = "(?:" + mysqlCatalogAggregateName + `\s*\(\s*(?:DISTINCT\s+)?` +
	mysqlCatalogAggregateArgs + `\s*\)|` + mysqlGroupConcatToken + ")"

var mysqlCatalogAggregateExpression = regexp.MustCompile(`(?is)^((` + mysqlCatalogAggregateName +
	`)\s*\(\s*(?:(DISTINCT)\s+)?(` + mysqlCatalogAggregateArgs + `)\s*\))(?:\s+(?:AS\s+)?(` +
	mysqlMetadataName + "|" + mysqlCatalogProjectionString + `))?$`)
var mysqlCatalogAggregateReferences = regexp.MustCompile(`(?is)` + mysqlCatalogProjectionString + `|` + mysqlCatalogAggregateToken)
var mysqlCatalogGroupEquality = regexp.MustCompile(`(?is)^\s*` + mysqlCatalogField + `\s*=\s*(?:` +
	mysqlCatalogProjectionString + `|\?|[+-]?\d+)(?:\s+AND\b|\s*$)`)

type mysqlCatalogAggregate struct {
	key, method    string
	distinct, star bool
	value          mysqlCatalogueJoinOperand
	concat         *mysqlGroupConcat
}

func mysqlCatalogAggregateKey(match []string) string {
	name := strings.ToLower(match[2]) + "("
	if match[3] != "" {
		name += "distinct "
	}
	arg := strings.TrimSpace(match[4])
	if field := mysqlCatalogObject.FindStringSubmatch(arg); field != nil {
		arg = strings.ToLower(mysqlUnquoteProjection(field[1]))
		if field[2] != "" {
			arg += "." + strings.ToLower(mysqlUnquoteProjection(field[2]))
		}
	}
	return name + arg + ")"
}

func (m *mysqlSimulation) catalogAggregateField(match []string, source mysqlCatalogSource, bindings *mysqlCatalogBindings) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	var field mysqlCatalogProjectionField
	arg := strings.TrimSpace(match[4])
	method := strings.ToLower(match[2])
	if method == "group_concat" {
		return m.catalogGroupConcat(match, source, bindings)
	}
	if len(mysqlSplitExpressions(arg)) != 1 {
		return field, &mysqlMetadataError{1105, "unsupported syntax: more than one expression in " + strings.ToUpper(method)}
	}
	a := &mysqlCatalogAggregate{key: mysqlCatalogAggregateKey(match), method: method, distinct: match[3] != "", star: arg == "*"}
	if arg == "?" && bindings != nil {
		a.key += "#" + strconv.Itoa(bindings.next)
	}
	label := match[1]
	if match[5] != "" {
		label = mysqlUnquoteProjection(match[5])
	}
	field = mysqlCatalogProjectionField{label: label, kind: 8, charset: 33, aggregate: a}
	if a.star {
		if method != "count" || a.distinct {
			return field, mysqlCatalogUnsupported()
		}
		return field, nil
	}
	parser := mysqlCatalogueJoinParser{source: source, bindings: bindings, database: m.current}
	var failure *mysqlMetadataError
	a.value, failure = parser.operand(arg)
	if failure != nil {
		return field, failure
	}
	if method == "count" && a.distinct && match[5] == "" && a.value.field.source != "" &&
		match[1] == "COUNT(DISTINCT "+arg+")" {
		qualifier := a.value.field.qualifier
		if qualifier == "" {
			qualifier = source.baseName
		}
		if qualifier != "" {
			field.label = "COUNT(DISTINCT " + strings.ToLower(qualifier) + "." + strings.ToLower(a.value.field.label) + ")"
		}
	}
	switch method {
	case "min", "max":
		if a.value.field.source != "" {
			field.kind, field.charset, field.flags = a.value.field.kind, a.value.field.charset, a.value.field.flags
		} else if a.value.numeric {
			literal, err := mysqlProjection(arg, "", "")
			if err == nil {
				field.kind, field.flags = literal.column.kind, literal.flags
			}
		} else {
			field.kind = 0xfc
		}
	case "sum", "avg":
		field.kind = 5
	}
	return field, nil
}

func (a *mysqlCatalogAggregate) evaluate(rows []mysqlCatalogRecord) (string, bool, *mysqlMetadataError) {
	if a.concat != nil {
		return a.concat.evaluate(rows, a.distinct)
	}
	if a.star {
		return strconv.Itoa(len(rows)), true, nil
	}
	var seen map[string]bool
	if a.distinct {
		seen = make(map[string]bool)
	}
	count, total, value := 0, float64(0), ""
	for _, row := range rows {
		text, present := a.value.value(row)
		if !present {
			continue
		}
		if seen != nil {
			if seen[text] {
				continue
			}
			seen[text] = true
		}
		switch a.method {
		case "min", "max":
			order := strings.Compare(text, value)
			if count > 0 && a.value.numeric {
				if cmp, valid := mysqlCatalogueNumericOrder(text, value); valid {
					order = cmp
				}
			}
			if count == 0 || a.method == "min" && order < 0 || a.method == "max" && order > 0 {
				value = text
			}
		case "sum", "avg":
			number, _ := strconv.ParseFloat(text, 64)
			total += number
		}
		count++
	}
	if a.method == "count" {
		return strconv.Itoa(count), true, nil
	}
	if count == 0 {
		return "", false, nil
	}
	if a.method == "avg" {
		total /= float64(count)
	}
	if a.method == "sum" || a.method == "avg" {
		value = strconv.FormatFloat(total, 'f', -1, 64)
	}
	return value, true, nil
}

func mysqlCatalogGroupingFields(raw string, source mysqlCatalogSource, projected []mysqlCatalogProjectionField) ([]mysqlCatalogProjectionField, *mysqlMetadataError) {
	if raw == "" {
		return nil, nil
	}
	var fields []mysqlCatalogProjectionField
	for _, expression := range mysqlSplitExpressions(raw) {
		var field mysqlCatalogProjectionField
		if position, err := strconv.Atoi(expression); err == nil {
			if position >= 1 && position <= len(projected) {
				field = projected[position-1]
			} else {
				// A numeric expression outside the projection refers to a constant.
				field.scalar = &mysqlExpression{text: expression, value: []byte{0}}
			}
		} else {
			name := mysqlUnquoteProjection(expression)
			i := slices.IndexFunc(projected, func(p mysqlCatalogProjectionField) bool { return strings.EqualFold(p.label, name) })
			if i >= 0 {
				field = projected[i]
			} else {
				var failure *mysqlMetadataError
				field, failure = source.resolve(expression)
				if failure != nil {
					return nil, failure
				}
			}
		}
		if field.aggregate != nil {
			return nil, &mysqlMetadataError{1105, fmt.Sprintf("column %q does not exist in scope, but there is an alias defined in this projection with that name. Aliases cannot be used in the same projection they're defined in", mysqlUnquoteProjection(expression))}
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func (m *mysqlSimulation) catalogueGroupedRows(rows []mysqlCatalogRecord, projected []mysqlCatalogProjectionField, source mysqlCatalogSource, clauses []string, bindings *mysqlCatalogBindings) ([]mysqlCatalogRecord, *mysqlMetadataError) {
	groups, failure := mysqlCatalogGroupingFields(clauses[1], source, projected)
	if failure != nil {
		return nil, failure
	}
	havingSource := source
	havingSource.fields = make(map[string]mysqlCatalogProjectionField, len(projected))
	havingSource.aggregateFields = make(map[string]mysqlCatalogProjectionField)
	for _, field := range projected {
		key := strings.ToLower(field.label)
		if _, exists := havingSource.fields[key]; !exists {
			havingSource.fields[key] = field
		}
		if field.qualifier != "" {
			havingSource.fields[field.qualifier+"."+key] = field
		}
		if field.aggregate != nil {
			havingSource.aggregateFields[field.aggregate.key] = field
		}
	}
	for _, raw := range mysqlCatalogAggregateReferences.FindAllString(clauses[2], -1) {
		match := mysqlCatalogParseAggregate(raw)
		if match == nil {
			continue
		}
		if strings.EqualFold(match[2], "GROUP_CONCAT") {
			return nil, &mysqlMetadataError{1105, fmt.Sprintf(
				"cannot find column %s referenced in HAVING clause in either GROUP BY or its child", mysqlGroupConcatDisplay(match))}
		}
		key := mysqlCatalogAggregateKey(match)
		if _, exists := havingSource.aggregateFields[key]; !exists {
			field, failure := m.catalogAggregateField(match, havingSource, bindings)
			if failure != nil {
				if failure.code == 1105 && strings.Contains(failure.message, "could not be found in any table in scope") {
					failure = mysqlCatalogColumnError(strings.TrimSpace(match[4]))
				}
				return nil, failure
			}
			havingSource.aggregateFields[key] = field
		}
	}
	having, failure := m.catalogWhere(clauses[2], havingSource, bindings)
	if failure != nil {
		return nil, failure
	}
	if len(groups) > 0 && mysqlCatalogGroupEquality.MatchString(clauses[0]) {
		for _, field := range projected {
			if field.scalar != nil || field.aggregate != nil {
				continue
			}
			if !slices.ContainsFunc(groups, func(key mysqlCatalogProjectionField) bool {
				return key.scalar == nil && key.slot == field.slot && key.source == field.source
			}) {
				name := field.source
				if field.qualifier != "" {
					name = field.qualifier + "." + name
				}
				return nil, &mysqlMetadataError{1105, fmt.Sprintf("expression '%s' doesn't appear in the group by expressions", name)}
			}
		}
	}
	if bindings != nil && bindings.preparing {
		return nil, nil
	}
	if len(groups) == 0 && len(havingSource.aggregateFields) == 0 {
		return mysqlApplyCatalogueHaving(rows, having)
	}
	partitions := mysqlCataloguePartitions(rows, groups)
	results := make([]mysqlCatalogRecord, 0, len(partitions))
	for _, partition := range partitions {
		var result mysqlCatalogRecord
		if len(partition) != 0 {
			result = partition[0]
		}
		result.aggregates = make(mysqlCatalogRow, len(havingSource.aggregateFields))
		for key, field := range havingSource.aggregateFields {
			value, present, failure := field.aggregate.evaluate(partition)
			if failure != nil {
				return nil, failure
			}
			if present {
				result.aggregates[key] = value
			}
		}
		results = append(results, result)
	}
	return mysqlApplyCatalogueHaving(results, having)
}

func mysqlCataloguePartitions(rows []mysqlCatalogRecord, fields []mysqlCatalogProjectionField) [][]mysqlCatalogRecord {
	if len(fields) == 0 {
		return [][]mysqlCatalogRecord{rows}
	}
	index := make(map[string]int)
	var groups [][]mysqlCatalogRecord
	for _, row := range rows {
		key := string(mysqlCatalogProjectRow(row, fields))
		i, exists := index[key]
		if !exists {
			i = len(groups)
			index[key] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], row)
	}
	return groups
}

func mysqlApplyCatalogueHaving(rows []mysqlCatalogRecord, having *mysqlWhereParser) ([]mysqlCatalogRecord, *mysqlMetadataError) {
	if having == nil {
		return rows, nil
	}
	rows = slices.DeleteFunc(rows, func(row mysqlCatalogRecord) bool {
		return having.failure != nil || having.test(row) != mysqlTrue
	})
	return rows, having.failure
}
