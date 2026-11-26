package protocols

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const mysqlCatalogJoinKind = `(?:(?:INNER|CROSS|(?:NATURAL\s+)?(?:LEFT|RIGHT)(?:\s+OUTER)?|NATURAL)\s+)?JOIN|STRAIGHT_JOIN`
const mysqlCatalogAlias = `(?:\s+(?:AS\s+)?(` + mysqlMetadataName + `))?`

var mysqlCatalogJoin = regexp.MustCompile(mysqlCatalogSelectPrefix + mysqlMetadataObject + mysqlCatalogAlias +
	`(?:\s+(` + mysqlCatalogJoinKind + `)\s+|\s*,\s*)` +
	mysqlMetadataObject + mysqlCatalogAlias + `(?:\s+(ON|USING)\s*(.+?))?` + mysqlCatalogSelectTail)

var mysqlCatalogQualifiedStar = regexp.MustCompile(`(?i)^(` + mysqlMetadataName + `)\s*\.\s*\*$`)

type mysqlCatalogSource struct {
	rows            []mysqlCatalogRecord
	columns         []mysqlCatalogProjectionField
	fields          map[string]mysqlCatalogProjectionField
	names           []string
	baseName        string
	postJoinFilters []func(mysqlCatalogRecord) bool
	depth           int
	outer           *mysqlCatalogScope
	calcFoundRows   bool
	aggregateFields map[string]mysqlCatalogProjectionField
}

func (s *mysqlCatalogSource) addField(field mysqlCatalogProjectionField, table string) {
	name := strings.ToLower(field.label)
	if table != "" {
		field.qualifier = strings.ToLower(table)
		qualified := field.qualifier + "." + name
		if _, exists := s.fields[qualified]; !exists {
			s.fields[qualified] = field
		}
	}
	if previous, duplicate := s.fields[name]; !duplicate {
		s.fields[name] = field
	} else if previous.qualifier != field.qualifier {
		// An empty source marks an ambiguous unqualified column.
		s.fields[name] = mysqlCatalogProjectionField{}
	}
	s.columns = append(s.columns, field)
}

func (s mysqlCatalogSource) resolve(raw string) (mysqlCatalogProjectionField, *mysqlMetadataError) {
	name := mysqlCatalogColumnName(raw)
	if len(s.names) != 0 || s.outer != nil {
		match := mysqlCatalogObject.FindStringSubmatch(raw)
		if match != nil && match[2] != "" {
			table := mysqlUnquoteProjection(match[1])
			if !s.hasTable(table) {
				if field, failure, found := s.outer.lookup(raw, name, table); found {
					return field, failure
				}
				return mysqlCatalogProjectionField{}, s.unknownTable(table)
			}
			if field, ok := s.fields[strings.ToLower(table)+"."+name]; ok {
				return field, nil
			}
			if field, failure, found := s.outer.lookup(raw, name, table); found {
				return field, failure
			}
			return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105,
				fmt.Sprintf("table %q does not have column %q", table, mysqlUnquoteProjection(match[2]))}
		}
	}
	if field, found := s.fields[name]; found {
		if field.source == "" && field.aggregate == nil && field.scalar == nil {
			return mysqlCatalogProjectionField{}, &mysqlMetadataError{1105,
				fmt.Sprintf("ambiguous column name %q, it's present in all these tables: %s",
					mysqlUnquoteProjection(raw), strings.Join(s.names, ", "))}
		}
		return field, nil
	}
	if field, failure, found := s.outer.lookup(raw, name, ""); found {
		return field, failure
	}
	return mysqlCatalogProjectionField{}, mysqlCatalogColumnError(name)
}

func (s mysqlCatalogSource) hasTable(name string) bool {
	for _, table := range s.names {
		if strings.EqualFold(table, name) {
			return true
		}
	}
	return false
}

func (s mysqlCatalogSource) unknownTable(name string) *mysqlMetadataError {
	names := slices.Clone(s.names)
	for outer := s.outer; outer != nil; outer = outer.source.outer {
		if slices.ContainsFunc(outer.hidden, func(alias string) bool { return strings.EqualFold(alias, name) }) {
			return &mysqlMetadataError{1146, "table not found: " + name}
		}
		for _, candidate := range outer.source.names {
			if !slices.ContainsFunc(names, func(existing string) bool { return strings.EqualFold(existing, candidate) }) {
				names = append(names, candidate)
			}
		}
	}
	return &mysqlMetadataError{1146, "table not found: " + name + ", maybe you mean " + strings.Join(names, " or ") + "?"}
}

func (s mysqlCatalogSource) star(table string) ([]mysqlCatalogProjectionField, *mysqlMetadataError) {
	name := mysqlUnquoteProjection(table)
	if len(s.names) == 0 {
		return s.columns, nil
	}
	if !s.hasTable(name) {
		return nil, s.unknownTable(name)
	}
	var fields []mysqlCatalogProjectionField
	for _, field := range s.columns {
		if strings.EqualFold(field.qualifier, name) {
			fields = append(fields, field)
		}
	}
	return fields, nil
}

type mysqlCatalogJoinSource struct {
	database, table, alias  string
	kind, clause, condition string
	subquery                string
	columns                 []string
}

type mysqlCatalogJoinQuery struct {
	distinct, projection string
	sources              []mysqlCatalogJoinSource
	tail                 []string
	calcFoundRows        bool
}

func (m *mysqlSimulation) catalogJoin(match []string, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope, calcFoundRows bool) (*mysqlCatalogResult, *mysqlMetadataError) {
	return m.catalogJoins(&mysqlCatalogJoinQuery{
		distinct: match[1], projection: match[2], tail: match[12:],
		calcFoundRows: calcFoundRows,
		sources: []mysqlCatalogJoinSource{
			{database: match[3], table: match[4], alias: match[5]},
			{database: match[7], table: match[8], alias: match[9], kind: match[6], clause: match[10], condition: match[11]},
		},
	}, bindings, depth, outer)
}

func (m *mysqlSimulation) catalogJoins(query *mysqlCatalogJoinQuery, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope) (*mysqlCatalogResult, *mysqlMetadataError) {
	hasCatalogue, allCatalogue := false, true
	for i, input := range query.sources {
		if input.subquery != "" {
			hasCatalogue = true
			continue
		}
		database, table := m.metadataObject(input.database, input.table)
		query.sources[i].database, query.sources[i].table = database, table
		isCatalogue := strings.EqualFold(database, "information_schema") || bindings != nil && bindings.unbound
		hasCatalogue = hasCatalogue || isCatalogue
		allCatalogue = allCatalogue && isCatalogue
	}
	if !hasCatalogue {
		return nil, nil
	}
	if !allCatalogue || len(query.sources) > mysqlMaxProjections {
		return nil, mysqlCatalogUnsupported()
	}
	lastRight := 0
	for slot, input := range query.sources {
		if strings.EqualFold(input.clause, "USING") {
			return nil, &mysqlMetadataError{1105, "unsupported feature: USING clause on join"}
		}
		kind := strings.Join(strings.Fields(strings.ToUpper(input.kind)), " ")
		query.sources[slot].kind = kind
		if len(query.sources) > 2 && kind == "STRAIGHT_JOIN" {
			return nil, &mysqlMetadataError{1105, "unsupported feature: Join type straight_join"}
		}
		if strings.HasPrefix(kind, "RIGHT ") {
			lastRight = slot
		}
	}

	projectionBindings := reserveMySQLProjectionBindings(query.projection, bindings)
	source := mysqlCatalogSource{fields: make(map[string]mysqlCatalogProjectionField), depth: depth, outer: outer,
		calcFoundRows: query.calcFoundRows}
	// Bound intermediate materialization for chains of Cartesian or broad joins.
	budget := 0
	if len(query.sources) > 2 {
		budget = 1 << 20
	}
	for slot, input := range query.sources {
		var hidden []string
		if input.subquery != "" {
			for other, sibling := range query.sources {
				if slot != other {
					name := mysqlUnquoteProjection(sibling.alias)
					if name == "" {
						name = sibling.table
					}
					hidden = append(hidden, name)
				}
			}
		}
		columns, data, failure := m.catalogJoinSource(input, bindings, depth, hidden)
		if failure != nil {
			return nil, failure
		}
		alias := mysqlUnquoteProjection(input.alias)
		if alias == "" {
			alias = input.table
		}
		if source.hasTable(alias) {
			return nil, mysqlCatalogUnsupported()
		}
		previous := len(source.columns)
		source.names = append(source.names, alias)
		for _, field := range columns {
			field.slot = slot
			source.addField(field, alias)
		}

		var plan mysqlCatalogueJoinPlan
		kind := input.kind
		outerLeft := strings.HasPrefix(kind, "LEFT ")
		outerRight := strings.HasPrefix(kind, "RIGHT ")
		switch {
		case kind == "NATURAL JOIN":
			if input.clause != "" {
				return nil, mysqlCatalogUnsupported()
			}
			plan = source.naturalJoin(previous)
		case input.clause != "":
			if strings.HasPrefix(kind, "NATURAL ") {
				return nil, mysqlCatalogUnsupported()
			}
			parser := mysqlCatalogueJoinParser{rest: input.condition, source: source, bindings: bindings, database: m.current}
			plan, failure = parser.parse()
			if failure != nil {
				return nil, failure
			}
			// With WHERE, the reference moves local predicates from preceding
			// inner joins past the later right join's match and padding step.
			if query.tail[0] != "" && slot < lastRight && (kind == "JOIN" || kind == "INNER JOIN" || kind == "CROSS JOIN") {
				source.postJoinFilters = append(source.postJoinFilters, plan.local...)
				plan.matches = plan.residual
			}
		case outerLeft || outerRight:
			return nil, mysqlCatalogUnsupported()
		}

		if bindings != nil && bindings.preparing {
			continue
		}
		records := mysqlCatalogueRecords(data, slot)
		if slot == 0 {
			source.rows = records
			continue
		}
		rows, ok := mysqlCatalogJoinedRows(source.rows, records, plan, slot, outerLeft || outerRight, outerRight, budget)
		if !ok {
			return nil, mysqlCatalogUnsupported()
		}
		if budget > 0 {
			budget -= len(rows)
			if budget == 0 && slot < len(query.sources)-1 {
				return nil, mysqlCatalogUnsupported()
			}
		}
		source.rows = rows
	}
	return m.selectCatalogue(query.distinct, query.projection, query.tail, source, bindings, projectionBindings)
}

// Natural outer syntax follows the Cartesian behavior of the reference. This
// function is only called for a natural inner join.
func (s *mysqlCatalogSource) naturalJoin(previous int) mysqlCatalogueJoinPlan {
	var plan mysqlCatalogueJoinPlan
	left := s.columns[:previous]
	columns := left
	for _, right := range s.columns[previous:] {
		name := strings.ToLower(right.label)
		i := slices.IndexFunc(left, func(field mysqlCatalogProjectionField) bool { return strings.EqualFold(field.label, name) })
		if i < 0 {
			columns = append(columns, right)
			continue
		}
		s.fields[name] = left[i]
		plan.left = append(plan.left, left[i])
		plan.right = append(plan.right, right)
	}
	s.columns = columns
	return plan
}

func mysqlCatalogueRecords(rows []mysqlCatalogRow, slot int) []mysqlCatalogRecord {
	records := make([]mysqlCatalogRecord, len(rows))
	for i, row := range rows {
		records[i] = mysqlCatalogRecord{row: row, slot: slot}
	}
	return records
}

func mysqlCatalogJoinedRows(left, right []mysqlCatalogRecord, plan mysqlCatalogueJoinPlan, slot int, outer, reverse bool, budget int) ([]mysqlCatalogRecord, bool) {
	leftKeys, rightKeys := plan.left, plan.right
	if reverse {
		left, right = right, left
		leftKeys, rightKeys = rightKeys, leftKeys
	}
	record := func(a, b *mysqlCatalogRecord) mysqlCatalogRecord {
		if reverse {
			a, b = b, a
		}
		row := mysqlCatalogRecord{previous: a, slot: slot}
		if b != nil {
			row.row = b.row
		}
		return row
	}
	index := make(map[string][]*mysqlCatalogRecord)
	if !plan.noMatches {
		for i := range right {
			if key, complete := mysqlCatalogueJoinKey(right[i], rightKeys); complete {
				index[key] = append(index[key], &right[i])
			}
		}
	}
	var rows []mysqlCatalogRecord
	for i := range left {
		a := &left[i]
		key, complete := mysqlCatalogueJoinKey(*a, leftKeys)
		first := len(rows)
		if complete {
			for _, b := range index[key] {
				row := record(a, b)
				if plan.matches == nil || plan.matches(row) {
					if budget > 0 && len(rows) == budget {
						return nil, false
					}
					rows = append(rows, row)
				}
			}
		}
		if outer && len(rows) == first {
			if budget > 0 && len(rows) == budget {
				return nil, false
			}
			rows = append(rows, record(a, nil))
		}
	}
	return rows, true
}

func mysqlCatalogueJoinKey(row mysqlCatalogRecord, fields []mysqlCatalogProjectionField) (string, bool) {
	var key []byte
	for _, field := range fields {
		value, present := row.value(field)
		if !present {
			return "", false
		}
		key = appendMySQLString(key, value)
	}
	return string(key), true
}
