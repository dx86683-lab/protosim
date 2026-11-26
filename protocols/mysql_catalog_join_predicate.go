package protocols

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const mysqlCatalogueJoinValue = `(?:'(?:[^']|'')*'|"(?:[^"]|"")*"|[+-]?\d+(?:\.\d+)?|\?|NULL\b|DATABASE\s*\(\s*\)|` + mysqlCatalogField + `)`

var mysqlCatalogueJoinTerm = regexp.MustCompile(`(?i)^(` + mysqlCatalogueJoinValue + `)(?:\s*(<=>|<=|>=|<>|!=|=|<|>)\s*(` +
	mysqlCatalogueJoinValue + `)|\s+LIKE\s+(` + mysqlCatalogueJoinValue + `)|\s+IS\s+(?:(NOT)\s+)?(NULL))`)

type mysqlCatalogueJoinPlan struct {
	left, right []mysqlCatalogProjectionField
	matches     func(mysqlCatalogRecord) bool
	residual    func(mysqlCatalogRecord) bool
	slots       uint64
	local       []func(mysqlCatalogRecord) bool
	noMatches   bool
}

func mysqlCatalogueJoinCondition(slots uint64, matches func(mysqlCatalogRecord) bool) mysqlCatalogueJoinPlan {
	plan := mysqlCatalogueJoinPlan{slots: slots, matches: matches}
	if slots&(slots-1) == 0 {
		plan.local = []func(mysqlCatalogRecord) bool{matches}
	} else {
		plan.residual = matches
	}
	return plan
}

type mysqlCatalogueJoinParser struct {
	rest     string
	source   mysqlCatalogSource
	bindings *mysqlCatalogBindings
	database string
	terms    int
}

func (p *mysqlCatalogueJoinParser) parse() (mysqlCatalogueJoinPlan, *mysqlMetadataError) {
	plan, failure := p.disjunction(0)
	if failure != nil {
		return mysqlCatalogueJoinPlan{}, failure
	}
	if strings.TrimSpace(p.rest) != "" {
		return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
	}
	return plan, nil
}

func (p *mysqlCatalogueJoinParser) keyword(word string) bool {
	rest := strings.TrimSpace(p.rest)
	if len(rest) < len(word) || !strings.EqualFold(rest[:len(word)], word) {
		return false
	}
	if len(rest) > len(word) {
		r, _ := utf8.DecodeRuneInString(rest[len(word):])
		if !unicode.IsSpace(r) && !strings.ContainsRune("(),", r) {
			return false
		}
	}
	p.rest = rest[len(word):]
	return true
}

func (p *mysqlCatalogueJoinParser) disjunction(depth int) (mysqlCatalogueJoinPlan, *mysqlMetadataError) {
	left, failure := p.conjunction(depth)
	for failure == nil && p.keyword("OR") {
		right, err := p.conjunction(depth)
		if err != nil {
			return mysqlCatalogueJoinPlan{}, err
		}
		a, b := left.matches, right.matches
		// An OR branch cannot supply a mandatory hash key.
		left = mysqlCatalogueJoinCondition(left.slots|right.slots, func(row mysqlCatalogRecord) bool {
			return a(row) || b(row)
		})
	}
	return left, failure
}

func (p *mysqlCatalogueJoinParser) conjunction(depth int) (mysqlCatalogueJoinPlan, *mysqlMetadataError) {
	left, failure := p.atomic(depth)
	for failure == nil && p.keyword("AND") {
		right, err := p.atomic(depth)
		if err != nil {
			return mysqlCatalogueJoinPlan{}, err
		}
		a, b := left.matches, right.matches
		left.matches = func(row mysqlCatalogRecord) bool { return a(row) && b(row) }
		left.residual = mysqlCatalogueJoinAnd(left.residual, right.residual)
		left.slots |= right.slots
		left.local = append(left.local, right.local...)
		left.left = append(left.left, right.left...)
		left.right = append(left.right, right.right...)
		left.noMatches = left.noMatches || right.noMatches
	}
	return left, failure
}

func mysqlCatalogueJoinAnd(a, b func(mysqlCatalogRecord) bool) func(mysqlCatalogRecord) bool {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	default:
		return func(row mysqlCatalogRecord) bool { return a(row) && b(row) }
	}
}

func (p *mysqlCatalogueJoinParser) atomic(depth int) (mysqlCatalogueJoinPlan, *mysqlMetadataError) {
	p.rest = strings.TrimSpace(p.rest)
	if strings.HasPrefix(p.rest, "(") {
		if depth >= mysqlMaxProjections {
			return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
		}
		p.rest = p.rest[1:]
		plan, failure := p.disjunction(depth + 1)
		if failure != nil {
			return mysqlCatalogueJoinPlan{}, failure
		}
		rest := strings.TrimSpace(p.rest)
		if !strings.HasPrefix(rest, ")") {
			return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
		}
		p.rest = rest[1:]
		return plan, nil
	}
	if p.terms >= mysqlMaxProjections {
		return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
	}
	match := mysqlCatalogueJoinTerm.FindStringSubmatch(p.rest)
	if match == nil {
		return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
	}
	p.terms++
	p.rest = p.rest[len(match[0]):]
	left, failure := p.operand(match[1])
	if failure != nil {
		return mysqlCatalogueJoinPlan{}, failure
	}
	if match[6] != "" {
		not := match[5] != ""
		return mysqlCatalogueJoinCondition(left.slots(), func(row mysqlCatalogRecord) bool {
			_, present := left.value(row)
			return present == not
		}), nil
	}
	if match[4] != "" {
		right, failure := p.operand(match[4])
		if failure != nil {
			return mysqlCatalogueJoinPlan{}, failure
		}
		if right.field.source != "" {
			return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
		}
		pattern, err := mysqlLikePattern(right.literal)
		if err != nil {
			return mysqlCatalogueJoinPlan{}, mysqlCatalogUnsupported()
		}
		return mysqlCatalogueJoinCondition(left.slots(), func(row mysqlCatalogRecord) bool {
			value, present := left.value(row)
			return present && right.present && pattern.MatchString(value)
		}), nil
	}
	right, failure := p.operand(match[3])
	if failure != nil {
		return mysqlCatalogueJoinPlan{}, failure
	}
	return mysqlCatalogueComparisonPlan(left, match[2], right, len(p.source.names)-1), nil
}

type mysqlCatalogueJoinOperand struct {
	field   mysqlCatalogProjectionField
	literal string
	present bool
	numeric bool
	read    func() (string, bool)
}

func (o mysqlCatalogueJoinOperand) slots() uint64 {
	if o.field.source == "" || o.field.scalar != nil {
		return 0
	}
	return uint64(1) << o.field.slot
}

func (o mysqlCatalogueJoinOperand) value(row mysqlCatalogRecord) (string, bool) {
	if o.read != nil {
		return o.read()
	}
	if o.field.source != "" || o.field.aggregate != nil || o.field.scalar != nil {
		return row.value(o.field)
	}
	return o.literal, o.present
}

func (p *mysqlCatalogueJoinParser) operand(raw string) (mysqlCatalogueJoinOperand, *mysqlMetadataError) {
	if strings.EqualFold(raw, "NULL") {
		return mysqlCatalogueJoinOperand{}, nil
	}
	if _, err := strconv.ParseFloat(raw, 64); err == nil {
		return mysqlCatalogueJoinOperand{literal: raw, present: true, numeric: true}, nil
	}
	if raw == "?" || raw[0] == '\'' || raw[0] == '"' || strings.Contains(raw, "(") {
		text, present, failure := p.bindings.operand(raw, p.database)
		boundNumber := false
		if raw == "?" && failure == nil && !p.bindings.preparing {
			kind := p.bindings.values[p.bindings.next-1].kind
			boundNumber = kind == 8 || kind == 5
		}
		return mysqlCatalogueJoinOperand{literal: text, present: present, numeric: boundNumber}, failure
	}
	field, failure := p.source.resolve(raw)
	return mysqlCatalogueJoinOperand{field: field, numeric: field.numeric()}, failure
}

func mysqlCatalogueComparisonPlan(left mysqlCatalogueJoinOperand, op string, right mysqlCatalogueJoinOperand, slot int) mysqlCatalogueJoinPlan {
	plan := mysqlCatalogueJoinCondition(left.slots()|right.slots(), func(row mysqlCatalogRecord) bool {
		a, hasA := left.value(row)
		b, hasB := right.value(row)
		if !hasA || !hasB {
			return op == "<=>" && !hasA && !hasB
		}
		order := strings.Compare(a, b)
		if left.numeric || right.numeric {
			var valid bool
			order, valid = mysqlCatalogueNumericOrder(a, b)
			if !valid {
				return false
			}
		}
		switch op {
		case "=", "<=>":
			return order == 0
		case "!=", "<>":
			return order != 0
		case "<":
			return order < 0
		case "<=":
			return order <= 0
		case ">":
			return order > 0
		case ">=":
			return order >= 0
		}
		return false
	})
	if left.slots() != 0 && right.slots() != 0 && (left.field.slot == slot) != (right.field.slot == slot) {
		if op == "<=>" {
			// A mandatory cross-source null-safe comparator produces no matches
			// in the measured reference plan. Scalar and OR branches still compare.
			plan.noMatches = true
		}
		if op == "=" && left.numeric == right.numeric {
			if left.field.slot == slot {
				left, right = right, left
			}
			plan.left = []mysqlCatalogProjectionField{left.field}
			plan.right = []mysqlCatalogProjectionField{right.field}
		}
	}
	return plan
}

func mysqlCatalogueNumericOrder(left, right string) (int, bool) {
	a, errA := strconv.ParseInt(left, 10, 64)
	b, errB := strconv.ParseInt(right, 10, 64)
	if errA == nil && errB == nil {
		return cmp.Compare(a, b), true
	}
	x, errA := strconv.ParseFloat(left, 64)
	y, errB := strconv.ParseFloat(right, 64)
	return cmp.Compare(x, y), errA == nil && errB == nil
}
