package protocols

import (
	"fmt"
	"strconv"
	"strings"
)

const mysqlMaxCatalogueDepth = 16

func (m *mysqlSimulation) catalogSubquery(query string, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope) (*mysqlCatalogResult, *mysqlMetadataError) {
	if depth >= mysqlMaxCatalogueDepth {
		return nil, mysqlCatalogUnsupported()
	}
	result, failure := m.catalogSelectDepth(query, bindings, depth, outer)
	if result != nil || failure != nil {
		return result, failure
	}
	result, failure = m.catalogNoSource(query, bindings, depth, outer, false, true)
	if result == nil && failure == nil {
		failure = mysqlCatalogUnsupported()
	}
	return result, failure
}

func (m *mysqlSimulation) catalogJoinSource(input mysqlCatalogJoinSource, bindings *mysqlCatalogBindings, depth int, hidden []string) ([]mysqlCatalogProjectionField, []mysqlCatalogRow, *mysqlMetadataError) {
	if input.subquery != "" {
		var scope *mysqlCatalogScope
		if len(hidden) != 0 {
			scope = &mysqlCatalogScope{hidden: hidden}
		}
		result, failure := m.catalogSubquery(input.subquery, bindings, depth+1, scope)
		if failure != nil {
			return nil, nil, failure
		}
		if len(input.columns) != 0 && len(input.columns) != len(result.columns) {
			return nil, nil, mysqlCatalogUnsupported()
		}
		fields := make([]mysqlCatalogProjectionField, len(result.columns))
		for i, field := range result.columns {
			// Column ordinals keep repeated labels distinct in wildcard output.
			field.source, field.qualifier = strconv.Itoa(i), ""
			field.scalar, field.aggregate = nil, nil
			if len(input.columns) != 0 {
				field.label = input.columns[i]
			}
			fields[i] = field
		}
		rows, failure := mysqlMaterializeCatalogue(result.rows, fields)
		return fields, rows, failure
	}
	if bindings != nil && bindings.unbound && !strings.EqualFold(input.database, "information_schema") {
		if input.database != m.schema || input.table != m.table {
			return nil, nil, &mysqlMetadataError{1146, "table not found: " + input.table}
		}
		fields := make([]mysqlCatalogProjectionField, 0, len(mysqlUserColumns))
		for _, column := range mysqlUserColumns {
			fields = append(fields, mysqlCatalogProjectionField{source: column.name, label: column.name, kind: column.kind, charset: 33})
		}
		var rows []mysqlCatalogRow
		if !bindings.preparing {
			stamp := mysqlSyntheticUsersCreated.Format("2006-01-02 15:04:05.999999")
			for _, user := range mysqlSyntheticUsers {
				rows = append(rows, mysqlCatalogRow{
					"name": user.name, "email": user.email, "phone_numbers": user.phone, "created_at": stamp,
				})
			}
		}
		return fields, rows, nil
	}
	table := strings.ToLower(input.table)
	columns, ok := mysqlInformationSchema[table]
	if !ok {
		return nil, nil, &mysqlMetadataError{1146, "table not found: " + input.table}
	}
	fields := make([]mysqlCatalogProjectionField, len(columns))
	for i, column := range columns {
		fields[i] = mysqlCatalogFieldDefinition(column)
	}
	var rows []mysqlCatalogRow
	if bindings == nil || !bindings.preparing {
		rows = m.catalogRows(table)
	}
	return fields, rows, nil
}

func mysqlMaterializeCatalogue(packets [][]byte, fields []mysqlCatalogProjectionField) ([]mysqlCatalogRow, *mysqlMetadataError) {
	rows := make([]mysqlCatalogRow, 0, len(packets))
	for _, packet := range packets {
		row := make(mysqlCatalogRow, len(fields))
		for _, field := range fields {
			if len(packet) == 0 {
				return nil, mysqlCatalogUnsupported()
			}
			if packet[0] == 0xfb {
				packet = packet[1:]
				continue
			}
			value, width := mysqlLengthEncodedParameter(packet)
			if width == 0 {
				return nil, mysqlCatalogUnsupported()
			}
			row[field.source] = string(value)
			packet = packet[width:]
		}
		if len(packet) != 0 {
			return nil, mysqlCatalogUnsupported()
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// A predicate subquery may resolve names from its enclosing SELECT. Derived
// tables pass no enclosing scope.
type mysqlCatalogScope struct {
	source mysqlCatalogSource
	row    *mysqlCatalogRecord
	used   bool
	hidden []string
}

func (scope *mysqlCatalogScope) lookup(raw, name, table string) (mysqlCatalogProjectionField, *mysqlMetadataError, bool) {
	if scope == nil {
		return mysqlCatalogProjectionField{}, nil, false
	}
	_, hasField := scope.source.fields[name]
	if table != "" {
		hasField = scope.source.hasTable(table)
	}
	if !hasField {
		field, failure, found := scope.source.outer.lookup(raw, name, table)
		scope.used = scope.used || found
		return field, failure, found
	}
	scope.used = true
	field, failure := scope.source.resolve(raw)
	if failure != nil {
		return field, failure, true
	}
	// An outer column is constant while scanning the current subquery.
	scalar := &mysqlExpression{}
	if scope.row != nil {
		if value, present := scope.row.value(field); present {
			scalar.text = value
			scalar.value = appendMySQLString(nil, value)
		}
	}
	field.scalar = scalar
	return field, nil, true
}

type mysqlWhereSubqueryRead func(mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError)

type mysqlWhereSubqueryResult struct {
	read    mysqlWhereSubqueryRead
	numeric bool
}

func (p *mysqlWhereParser) singleColumnSubquery(query string) (mysqlWhereSubqueryResult, *mysqlMetadataError) {
	var output mysqlWhereSubqueryResult
	outer := &mysqlCatalogScope{source: p.source}
	probe := mysqlCatalogBindings{preparing: true}
	if p.bindings != nil {
		probe.next = p.bindings.next
	}
	result, failure := p.model.catalogSubquery(query, &probe, p.source.depth+1, outer)
	if failure != nil {
		return output, failure
	}
	if len(result.columns) != 1 {
		return output, &mysqlMetadataError{1241, fmt.Sprintf("operand should have 1 columns, but has %d", len(result.columns))}
	}
	output.numeric = result.columns[0].numeric()
	first := 0
	if p.bindings != nil {
		first, p.bindings.next = p.bindings.next, probe.next
	}
	switch {
	case p.bindings != nil && p.bindings.preparing:
		// Only the nested query's metadata and parameter count are needed.
		output.read = func(mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError) { return nil, nil }
	case probe.next > first:
		// The reference counts these placeholders but does not bind them.
		failure := mysqlCatalogUnboundVariable(first)
		output.read = func(mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError) { return nil, failure }
	case outer.used:
		output.read = func(row mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError) {
			scope := &mysqlCatalogScope{source: p.source, row: &row}
			result, failure := p.model.catalogSubquery(query, nil, p.source.depth+1, scope)
			if failure != nil {
				return nil, failure
			}
			return mysqlCatalogueSubqueryValues(result, output.numeric)
		}
	default:
		result, failure := p.model.catalogSubquery(query, nil, p.source.depth+1, nil)
		if failure != nil {
			return output, failure
		}
		values, failure := mysqlCatalogueSubqueryValues(result, output.numeric)
		if failure != nil {
			return output, failure
		}
		output.read = func(mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError) { return values, nil }
	}
	return output, nil
}

func mysqlCatalogueSubqueryValues(result *mysqlCatalogResult, numeric bool) ([]mysqlWhereValue, *mysqlMetadataError) {
	values := make([]mysqlWhereValue, 0, len(result.rows))
	for _, packet := range result.rows {
		value, width := mysqlLengthEncodedParameter(packet)
		present := width != 0
		if (present && width != len(packet)) || (!present && (len(packet) != 1 || packet[0] != 0xfb)) {
			return nil, mysqlCatalogUnsupported()
		}
		text := string(value)
		values = append(values, mysqlWhereValue{
			numeric: numeric,
			value:   func(mysqlCatalogRecord) (string, bool) { return text, present },
		})
	}
	return values, nil
}
