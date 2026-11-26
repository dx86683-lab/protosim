package protocols

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const mysqlCatalogField = `(?:` + mysqlMetadataName + `\s*\.\s*)?` + mysqlMetadataName
const mysqlCatalogSelectPrefix = "(?is)^SELECT\\s+(?:(DISTINCT)\\s+)?((?:'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`(?:[^`]|``)*`|[^'\"`])+?)\\s+FROM\\s+"
const mysqlCatalogSelectTail = `(?:\s+WHERE\s+(.+?))?(?:\s+GROUP\s+BY\s+(.+?))?(?:\s+HAVING\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?` +
	`(?:\s+LIMIT\s+([0-9]+|\?)(?:\s*,\s*([0-9]+|\?)|\s+OFFSET\s+([0-9]+|\?))?)?$`

var mysqlCatalogSelect = regexp.MustCompile(mysqlCatalogSelectPrefix + mysqlMetadataObject +
	mysqlCatalogAlias + mysqlCatalogSelectTail)
var mysqlCatalogProjection = regexp.MustCompile(`(?i)^(` + mysqlCatalogField + `)(?:\s+(?:AS\s+)?(` + mysqlMetadataName + `))?$`)
var mysqlCatalogOrder = regexp.MustCompile(`(?i)^(` + mysqlCatalogAggregateToken + `|` + mysqlProjectionNumber + `|` + mysqlCatalogProjectionString + `|` + mysqlCatalogField + `)(?:\s+(ASC|DESC))?$`)
var mysqlCatalogOrderNumber = regexp.MustCompile(`(?i)^` + mysqlProjectionNumber + `$`)
var mysqlCatalogObject = regexp.MustCompile(`(?i)^` + mysqlMetadataObject + `$`)

type mysqlCatalogRow map[string]string // A missing field is SQL NULL.

type mysqlCatalogRecord struct {
	row        mysqlCatalogRow
	aggregates mysqlCatalogRow
	previous   *mysqlCatalogRecord
	slot       int
}

func (r mysqlCatalogRecord) value(field mysqlCatalogProjectionField) (string, bool) {
	if field.aggregate != nil {
		value, present := r.aggregates[field.aggregate.key]
		return value, present
	}
	if field.scalar != nil {
		return field.scalar.text, field.scalar.value != nil
	}
	for current := &r; current != nil && current.slot >= field.slot; current = current.previous {
		if current.slot == field.slot {
			value, present := current.row[field.source]
			return value, present
		}
	}
	return "", false
}

type mysqlCatalogResult struct {
	columns   []mysqlCatalogProjectionField
	rows      [][]byte
	foundRows *uint64
}

type mysqlCatalogProjectionField struct {
	source    string
	qualifier string
	label     string
	kind      byte
	charset   byte
	flags     byte
	aggregate *mysqlCatalogAggregate
	slot      int
	scalar    *mysqlExpression
}

func (f mysqlCatalogProjectionField) numeric() bool {
	switch f.kind {
	case 1, 2, 3, 4, 5, 8, 9, 13:
		return true
	default:
		return false
	}
}

//go:embed fixtures/mysql-collations.json
var mysqlCollationsJSON []byte

var mysqlCollationRows = func() []mysqlCatalogRow {
	var values [][]string
	if err := json.Unmarshal(mysqlCollationsJSON, &values); err != nil {
		panic(err)
	}
	fields := mysqlInformationSchema["collations"]
	rows := make([]mysqlCatalogRow, 0, len(values))
	for _, values := range values {
		if len(values) != len(fields) {
			panic("invalid synthetic MySQL collation row")
		}
		row := make(mysqlCatalogRow, len(fields))
		for i, field := range fields {
			row[field.Name] = values[i]
		}
		rows = append(rows, row)
	}
	return rows
}()

func mysqlCatalogFieldDefinition(column mysqlMetadataColumn) mysqlCatalogProjectionField {
	field := mysqlCatalogProjectionField{source: column.Name, label: column.Name, kind: 0xfc, charset: 33}
	switch {
	case strings.HasPrefix(column.Type, "varchar("):
		field.kind = 0xfd
	case column.Type == "bigint":
		field.kind = 8
	case column.Type == "bigint unsigned":
		field.kind, field.flags = 8, 0x20
	case column.Type == "tinyint unsigned":
		field.kind, field.flags = 1, 0x20
	case column.Type == "timestamp":
		field.kind = 7
	case column.Type == "datetime":
		field.kind, field.flags = 12, 0x80
	case column.Type == "longblob":
		field.charset, field.flags = 63, 0x80
	case column.Type == "json":
		field.kind = 0xf5
	}
	return field
}

func mysqlCatalogColumnName(field string) string {
	if match := mysqlCatalogObject.FindStringSubmatch(field); match != nil && match[2] != "" {
		field = match[2]
	}
	return strings.ToLower(mysqlUnquoteProjection(field))
}

func mysqlCatalogColumnError(name string) *mysqlMetadataError {
	return &mysqlMetadataError{1105, fmt.Sprintf("column %q could not be found in any table in scope", name)}
}

func mysqlCatalogUnsupported() *mysqlMetadataError {
	return &mysqlMetadataError{1105, "query not supported by simulator"}
}

func (m *mysqlSimulation) catalogSelect(query string, bindings *mysqlCatalogBindings) (*mysqlCatalogResult, *mysqlMetadataError) {
	return m.catalogSelectDepth(query, bindings, 0, nil)
}

func (m *mysqlSimulation) catalogSelectDepth(query string, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope) (*mysqlCatalogResult, *mysqlMetadataError) {
	if branches, failure := mysqlCatalogUnionBranches(query); failure != nil {
		return nil, failure
	} else if branches != nil {
		return m.catalogUnion(branches, bindings, depth, outer)
	}
	if failure := mysqlGroupConcatSyntax(query); failure != nil {
		return nil, failure
	}
	query, calcFoundRows, failure := mysqlCatalogueSelectOptions(query)
	if failure != nil {
		return nil, failure
	}
	if chain, failure := mysqlCatalogJoinChain(query, depth > 0); failure != nil {
		return nil, failure
	} else if chain != nil {
		chain.calcFoundRows = calcFoundRows
		return m.catalogJoins(chain, bindings, depth, outer)
	}
	if join := mysqlCatalogJoin.FindStringSubmatch(query); join != nil {
		return m.catalogJoin(join, bindings, depth, outer, calcFoundRows)
	}
	match := mysqlCatalogSelect.FindStringSubmatch(query)
	if match == nil {
		return m.catalogNoSource(query, bindings, depth, outer, calcFoundRows, false)
	}
	database, requested := m.metadataObject(match[3], match[4])
	if !strings.EqualFold(database, "information_schema") {
		return nil, nil
	}
	table := strings.ToLower(requested)
	definition, ok := mysqlInformationSchema[table]
	if !ok {
		return nil, &mysqlMetadataError{1146, "table not found: " + requested}
	}
	var rows []mysqlCatalogRow
	if bindings == nil || !bindings.preparing {
		rows = m.catalogRows(table)
	}

	source := mysqlCatalogSource{
		rows:          make([]mysqlCatalogRecord, 0, len(rows)),
		fields:        make(map[string]mysqlCatalogProjectionField, len(definition)),
		depth:         depth,
		outer:         outer,
		calcFoundRows: calcFoundRows,
		baseName:      mysqlUnquoteProjection(match[5]),
	}
	if source.baseName == "" {
		source.baseName = table
	}
	for _, row := range rows {
		source.rows = append(source.rows, mysqlCatalogRecord{row: row})
	}
	for _, col := range definition {
		source.addField(mysqlCatalogFieldDefinition(col), "")
	}
	return m.selectCatalogue(match[1], match[2], match[6:], source, bindings, reserveMySQLProjectionBindings(match[2], bindings))
}

func (m *mysqlSimulation) selectCatalogue(distinct, projection string, clauses []string, source mysqlCatalogSource, bindings, projectionBindings *mysqlCatalogBindings) (*mysqlCatalogResult, *mysqlMetadataError) {
	all, rows := source.columns, source.rows
	where, failure := m.catalogWhere(clauses[0], source, bindings)
	if failure != nil {
		return nil, failure
	}
	projected := all
	if strings.TrimSpace(projection) != "*" {
		projected = nil
		expressions := mysqlSplitExpressions(projection)
		if len(expressions) > mysqlMaxProjections {
			return nil, mysqlCatalogUnsupported()
		}
		for _, expression := range expressions {
			if bindings != nil && bindings.unbound {
				expression = mysqlCatalogUngroupProjection(expression)
			}
			if expression == "*" {
				projected = append(projected, all...)
				continue
			}
			if wildcard := mysqlCatalogQualifiedStar.FindStringSubmatch(expression); wildcard != nil {
				columns, failure := source.star(wildcard[1])
				if failure != nil {
					return nil, failure
				}
				projected = append(projected, columns...)
				continue
			}
			if aggregate := mysqlCatalogParseAggregate(expression); aggregate != nil {
				field, failure := m.catalogAggregateField(aggregate, source, projectionBindings)
				if failure != nil {
					return nil, failure
				}
				projected = append(projected, field)
				continue
			}
			scalar, failure := m.catalogScalarProjection(expression, projectionBindings)
			if failure != nil {
				return nil, failure
			}
			if scalar.scalar != nil {
				projected = append(projected, scalar)
				continue
			}
			column := mysqlCatalogProjection.FindStringSubmatch(expression)
			if column == nil {
				return nil, mysqlCatalogUnsupported()
			}
			field, failure := source.resolve(column[1])
			if failure != nil {
				return nil, failure
			}
			if column[2] != "" {
				field.label = mysqlUnquoteProjection(column[2])
			}
			projected = append(projected, field)
		}
		if len(projected) == 0 || len(projected) > 250 {
			return nil, mysqlCatalogUnsupported()
		}
	}

	rows = slices.DeleteFunc(rows, func(row mysqlCatalogRecord) bool {
		return where != nil && (where.failure != nil || where.test(row) != mysqlTrue) || slices.ContainsFunc(source.postJoinFilters, func(accept func(mysqlCatalogRecord) bool) bool {
			return !accept(row)
		})
	})
	deferWhereFailure := bindings != nil && bindings.unbound && slices.Contains(clauses[4:], "?")
	if where != nil && where.failure != nil && !deferWhereFailure {
		return nil, where.failure
	}
	if clauses[1] != "" || clauses[2] != "" || slices.ContainsFunc(projected, func(field mysqlCatalogProjectionField) bool { return field.aggregate != nil }) {
		rows, failure = m.catalogueGroupedRows(rows, projected, source, clauses, bindings)
		if failure != nil {
			return nil, failure
		}
	}
	if clauses[3] != "" {
		if failure := sortMySQLCatalogRows(rows, clauses[3], source, projected); failure != nil {
			return nil, failure
		}
	}
	first, failure := bindings.limit(clauses[4], m.current, uint64(m.selectLimit()))
	if failure != nil {
		return nil, failure
	}
	offset, count := uint64(0), first
	if clauses[5] != "" {
		offset = first
		count, failure = bindings.limit(clauses[5], m.current, 0)
	} else if clauses[6] != "" {
		offset, failure = bindings.limit(clauses[6], m.current, 0)
	}
	if failure != nil {
		return nil, failure
	}
	if where != nil && where.failure != nil {
		return nil, where.failure
	}
	result := &mysqlCatalogResult{columns: projected}
	foundRows := uint64(len(rows))
	if source.calcFoundRows {
		result.foundRows = &foundRows
	}
	switch {
	case count == 0 && (!source.calcFoundRows || distinct == ""):
		return result, nil
	case distinct == "":
		// Only encode the rows that survive OFFSET and LIMIT.
		rows = rows[min(offset, uint64(len(rows))):]
		rows = rows[:min(count, uint64(len(rows)))]
		for _, row := range rows {
			result.rows = append(result.rows, mysqlCatalogProjectRow(row, projected))
		}
	default:
		seen := make(map[string]bool)
		for _, row := range rows {
			packet := mysqlCatalogProjectRow(row, projected)
			key := string(packet)
			if seen[key] {
				continue
			}
			seen[key] = true
			if offset != 0 {
				offset--
				continue
			}
			if uint64(len(result.rows)) < count {
				result.rows = append(result.rows, packet)
			}
			if !source.calcFoundRows && uint64(len(result.rows)) == count {
				break
			}
		}
		foundRows = uint64(len(seen))
	}
	if len(result.rows) != 0 && (bindings == nil || !bindings.preparing) {
		for _, field := range projected {
			if field.scalar != nil && field.scalar.contextError != "" {
				return nil, &mysqlMetadataError{1105, field.scalar.contextError}
			}
		}
	}
	return result, nil
}

func mysqlCatalogProjectRow(row mysqlCatalogRecord, fields []mysqlCatalogProjectionField) []byte {
	var packet []byte
	for _, field := range fields {
		if value, present := row.value(field); present {
			packet = appendMySQLString(packet, value)
		} else {
			packet = append(packet, 0xfb)
		}
	}
	return packet
}

func mysqlCatalogueOrderField(raw string, source mysqlCatalogSource, projected []mysqlCatalogProjectionField) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	if mysqlCatalogOrderNumber.MatchString(raw) {
		return mysqlCatalogueOrderOrdinal(raw, projected)
	}
	if raw[0] == '\'' || raw[0] == '"' {
		return mysqlCatalogProjectionField{}, nil // A string literal does not affect the order.
	}
	name := mysqlUnquoteProjection(raw)
	if group := mysqlGroupConcatExpression.FindStringSubmatch(raw); group != nil {
		return mysqlCatalogProjectionField{}, mysqlCatalogColumnError(mysqlGroupConcatDisplay(group))
	}
	match := mysqlCatalogAggregateExpression.FindStringSubmatch(raw)
	for _, field := range projected {
		if strings.EqualFold(field.label, name) ||
			match != nil && field.aggregate != nil && field.aggregate.key == mysqlCatalogAggregateKey(match) {
			return field, nil
		}
	}
	if match != nil {
		return mysqlCatalogProjectionField{}, mysqlCatalogColumnError(raw)
	}
	return source.resolve(raw)
}

func mysqlCatalogueOrderOrdinal(raw string, projected []mysqlCatalogProjectionField) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	value := strings.TrimPrefix(raw, "+")
	if strings.ContainsAny(value, ".eE") {
		n, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105, err.Error()}
		}
		n = math.Trunc(n)
		if n == 0 {
			value = "0"
		} else {
			value = strconv.FormatFloat(n, 'f', 0, 64)
		}
	}
	if strings.HasPrefix(value, "-") {
		position, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105, err.Error()}
		}
		value = strconv.FormatInt(position, 10)
	} else {
		position, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105, err.Error()}
		}
		if position > 0 && position <= uint64(len(projected)) {
			return projected[position-1], nil
		}
		value = strconv.FormatUint(position, 10)
	}
	return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105, "unknown column " + value + " in order by clause"}
}

func sortMySQLCatalogRows(rows []mysqlCatalogRecord, orderBy string, source mysqlCatalogSource, projected []mysqlCatalogProjectionField) *mysqlMetadataError {
	type orderField struct {
		field mysqlCatalogProjectionField
		desc  bool
	}
	var ordering []orderField
	for _, key := range mysqlSplitExpressions(orderBy) {
		match := mysqlCatalogOrder.FindStringSubmatch(key)
		if match == nil {
			return mysqlCatalogUnsupported()
		}
		field, failure := mysqlCatalogueOrderField(match[1], source, projected)
		if failure != nil {
			return failure
		}
		ordering = append(ordering, orderField{field, strings.EqualFold(match[2], "DESC")})
	}
	if len(ordering) == 0 || len(ordering) > mysqlMaxProjections {
		return mysqlCatalogUnsupported()
	}
	slices.SortStableFunc(rows, func(left, right mysqlCatalogRecord) int {
		for _, order := range ordering {
			a, aOK := left.value(order.field)
			b, bOK := right.value(order.field)
			var result int
			switch {
			case aOK && !bOK:
				result = 1
			case !aOK && bOK:
				result = -1
			case order.field.numeric() && order.field.flags&0x20 != 0:
				x, _ := strconv.ParseUint(a, 10, 64)
				y, _ := strconv.ParseUint(b, 10, 64)
				result = cmp.Compare(x, y)
			case order.field.kind == 4 || order.field.kind == 5:
				x, _ := strconv.ParseFloat(a, 64)
				y, _ := strconv.ParseFloat(b, 64)
				result = cmp.Compare(x, y)
			case order.field.numeric():
				x, _ := strconv.ParseInt(a, 10, 64)
				y, _ := strconv.ParseInt(b, 10, 64)
				result = cmp.Compare(x, y)
			default:
				result = strings.Compare(a, b)
			}
			if result != 0 {
				if order.desc {
					return -result
				}
				return result
			}
		}
		return 0
	})
	return nil
}

func (m *mysqlSimulation) catalogRows(table string) []mysqlCatalogRow {
	const information = "information_schema"
	const collation = "utf8mb4_0900_bin"
	var rows []mysqlCatalogRow
	switch table {
	case "character_sets":
		return []mysqlCatalogRow{{"character_set_name": "utf8mb4", "default_collate_name": "utf8mb4_0900_ai_ci",
			"description": "UTF-8 Unicode", "maxlen": "4"}}
	case "collations":
		// Filtering and ordering mutate the slice, but the row maps are read-only.
		return slices.Clone(mysqlCollationRows)
	case "engines":
		return []mysqlCatalogRow{{"engine": "InnoDB", "support": "DEFAULT",
			"comment":      "Supports transactions, row-level locking, and foreign keys",
			"transactions": "YES", "xa": "YES", "savepoints": "YES"}}
	case "schemata":
		for _, schema := range []string{m.schema, information} {
			rows = append(rows, mysqlCatalogRow{"catalog_name": "def", "schema_name": schema,
				"default_character_set_name": "utf8mb4", "default_collation_name": collation})
		}
	case "tables", "columns":
		for _, schema := range []string{m.schema, information} {
			tables, tableType, engine, rowFormat := []string{m.table}, "BASE TABLE", "INNODB", "Dynamic"
			if schema == information {
				tables, tableType, engine, rowFormat = mysqlInfoTables, "SYSTEM VIEW", "MEMORY", "Fixed"
			}
			for _, name := range tables {
				if table == "tables" {
					rows = append(rows, mysqlCatalogRow{
						"table_catalog": "def", "table_schema": schema, "table_name": name, "table_type": tableType,
						"engine": engine, "version": "10", "row_format": rowFormat, "table_comment": "",
						"create_time": "2000-01-01 00:00:00", "update_time": "2000-01-01 00:00:00", "table_collation": collation,
					})
					continue
				}
				_, columns, _ := m.metadataTable(schema, name)
				for i, column := range columns {
					row := mysqlCatalogRow{
						"table_catalog": "def", "table_schema": schema, "table_name": name, "column_name": column.Name,
						"ordinal_position": strconv.Itoa(i), "column_default": column.Default, "is_nullable": "NO",
						"data_type": column.Type, "column_type": column.Type, "column_key": "", "extra": "",
						"privileges": "select", "column_comment": "", "generation_expression": "",
					}
					if column.Nullable {
						row["is_nullable"] = "YES"
					}
					if strings.HasSuffix(column.Type, "text") || strings.HasPrefix(column.Type, "varchar(") || column.Type == "longblob" {
						row["character_set_name"], row["collation_name"] = "utf8mb4", collation
					}
					rows = append(rows, row)
				}
			}
		}
	}
	// The remaining views have a catalogue definition but no synthetic rows.
	return rows
}
