package protocols

import (
	"cmp"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var mysqlWhereOperand = regexp.MustCompile(`(?i)^(?:` + mysqlCatalogProjectionString + `|` + mysqlCatalogAggregateToken + `|` +
	mysqlProjectionNumber + `|\?|(?:NULL|TRUE|FALSE)\b|DATABASE\s*\(\s*\)|` + mysqlCatalogField + `)`)
var mysqlWhereComparison = regexp.MustCompile(`^(<=>|<=|>=|<>|!=|=|<|>)`)

type mysqlTruth int8

const (
	mysqlFalse   mysqlTruth = -1
	mysqlUnknown mysqlTruth = 0
	mysqlTrue    mysqlTruth = 1
)

func mysqlBoolean(ok bool) mysqlTruth {
	if ok {
		return mysqlTrue
	}
	return mysqlFalse
}

type mysqlWherePredicate func(mysqlCatalogRecord) mysqlTruth

type mysqlWhereValue struct {
	value   func(mysqlCatalogRecord) (string, bool)
	numeric bool
}

type mysqlWhereParser struct {
	mysqlCatalogueJoinParser
	failure *mysqlMetadataError
	test    mysqlWherePredicate
	model   *mysqlSimulation
}

func (m *mysqlSimulation) catalogWhere(where string, source mysqlCatalogSource, bindings *mysqlCatalogBindings) (*mysqlWhereParser, *mysqlMetadataError) {
	if strings.TrimSpace(where) == "" {
		return nil, nil
	}
	parser := &mysqlWhereParser{model: m, mysqlCatalogueJoinParser: mysqlCatalogueJoinParser{
		rest: where, source: source, bindings: bindings, database: m.current,
	}}
	predicate, failure := parser.expression(1, 0)
	if failure != nil {
		return nil, failure
	}
	if strings.TrimSpace(parser.rest) != "" {
		return nil, mysqlCatalogUnsupported()
	}
	parser.test = predicate
	return parser, nil
}

// OR has precedence 1. AND has precedence 2.
func (p *mysqlWhereParser) expression(precedence, depth int) (mysqlWherePredicate, *mysqlMetadataError) {
	if depth >= mysqlMaxProjections {
		return nil, mysqlCatalogUnsupported()
	}
	left, failure := p.predicate(depth)
	for failure == nil {
		isAnd := precedence <= 2 && p.keyword("AND")
		if !isAnd && (precedence > 1 || !p.keyword("OR")) {
			break
		}
		next := 2
		if isAnd {
			next = 3
		}
		right, err := p.expression(next, depth+1)
		if err != nil {
			return nil, err
		}
		previous := left
		left = func(row mysqlCatalogRecord) mysqlTruth {
			value := previous(row)
			if p.failure != nil || isAnd && value == mysqlFalse || !isAnd && value == mysqlTrue {
				return value
			}
			if isAnd {
				return min(value, right(row))
			}
			return max(value, right(row))
		}
	}
	return left, failure
}

func (p *mysqlWhereParser) punctuation(token string) bool {
	rest := strings.TrimSpace(p.rest)
	if !strings.HasPrefix(rest, token) {
		return false
	}
	p.rest = rest[len(token):]
	return true
}

func (p *mysqlWhereParser) predicate(depth int) (mysqlWherePredicate, *mysqlMetadataError) {
	if depth >= mysqlMaxProjections {
		return nil, mysqlCatalogUnsupported()
	}
	if p.keyword("NOT") {
		child, failure := p.predicate(depth + 1)
		return func(row mysqlCatalogRecord) mysqlTruth { return -child(row) }, failure
	}
	if p.keyword("EXISTS") {
		if query, _, ok := mysqlCatalogSplitGroup(p.rest); ok {
			if text, ok := mysqlDiagnosticSelect(query); ok {
				return nil, &mysqlMetadataError{1105, "unsupported syntax: exists (" + text + ")"}
			}
		}
		return nil, mysqlCatalogUnsupported()
	}
	if p.punctuation("(") {
		child, failure := p.expression(1, depth+1)
		if failure != nil {
			return nil, failure
		}
		if !p.punctuation(")") {
			return nil, mysqlCatalogUnsupported()
		}
		return child, nil
	}
	left, failure := p.scalar(1)
	if failure != nil {
		return nil, failure
	}
	if op := mysqlWhereComparison.FindString(strings.TrimSpace(p.rest)); op != "" {
		p.punctuation(op)
		right, failure := p.scalar(1)
		return func(row mysqlCatalogRecord) mysqlTruth {
			return mysqlWhereCompare(row, left, op, right, left.numeric || right.numeric)
		}, failure
	}

	negated := p.keyword("NOT")
	var predicate mysqlWherePredicate
	switch {
	case !negated && p.keyword("IS"):
		not := p.keyword("NOT")
		want := mysqlUnknown
		switch {
		case p.keyword("NULL"):
		case p.keyword("TRUE"):
			want = mysqlTrue
		case p.keyword("FALSE"):
			want = mysqlFalse
		default:
			return nil, mysqlCatalogUnsupported()
		}
		predicate = func(row mysqlCatalogRecord) mysqlTruth {
			if want == mysqlUnknown {
				_, present := left.value(row)
				return mysqlBoolean(present == not)
			}
			return mysqlBoolean((mysqlWhereTruth(left, row) == want) != not)
		}
	case p.keyword("BETWEEN"):
		lower, err := p.scalar(1)
		if err != nil {
			return nil, err
		}
		if !p.keyword("AND") {
			return nil, mysqlCatalogUnsupported()
		}
		upper, err := p.scalar(1)
		if err != nil {
			return nil, err
		}
		predicate = func(row mysqlCatalogRecord) mysqlTruth {
			return min(mysqlWhereCompare(row, left, ">=", lower, left.numeric),
				mysqlWhereCompare(row, left, "<=", upper, left.numeric))
		}
	case p.keyword("IN"):
		predicate, failure = p.in(left)
	case p.keyword("LIKE"):
		predicate, failure = p.pattern(left, true)
	case p.keyword("REGEXP") || p.keyword("RLIKE"):
		predicate, failure = p.pattern(left, false)
	case negated:
		return nil, mysqlCatalogUnsupported()
	default:
		predicate = func(row mysqlCatalogRecord) mysqlTruth { return mysqlWhereTruth(left, row) }
	}
	if failure != nil || !negated {
		return predicate, failure
	}
	return func(row mysqlCatalogRecord) mysqlTruth { return -predicate(row) }, nil
}

func (p *mysqlWhereParser) in(left mysqlWhereValue) (mysqlWherePredicate, *mysqlMetadataError) {
	if query, rest, ok := mysqlCatalogSplitGroup(p.rest); ok && mysqlCatalogSelectStart.MatchString(query) {
		p.rest = rest
		result, failure := p.singleColumnSubquery(query)
		if failure != nil {
			return nil, failure
		}
		return p.membership(left, result.read), nil
	}
	if !p.punctuation("(") {
		return nil, mysqlCatalogUnsupported()
	}
	var values []mysqlWhereValue
	for {
		value, failure := p.scalar(1)
		if failure != nil {
			return nil, failure
		}
		values = append(values, value)
		if !p.punctuation(",") {
			break
		}
	}
	if !p.punctuation(")") {
		return nil, mysqlCatalogUnsupported()
	}
	return p.membership(left, func(mysqlCatalogRecord) ([]mysqlWhereValue, *mysqlMetadataError) {
		return values, nil
	}), nil
}

func (p *mysqlWhereParser) membership(left mysqlWhereValue, read mysqlWhereSubqueryRead) mysqlWherePredicate {
	return func(row mysqlCatalogRecord) mysqlTruth {
		values, failure := read(row)
		if failure != nil {
			p.failure = failure
			return mysqlUnknown
		}
		result := mysqlFalse
		for _, value := range values {
			result = max(result, mysqlWhereCompare(row, left, "=", value, left.numeric || value.numeric))
			if result == mysqlTrue {
				break
			}
		}
		return result
	}
}

func (p *mysqlWhereParser) pattern(left mysqlWhereValue, like bool) (mysqlWherePredicate, *mysqlMetadataError) {
	right, failure := p.atom()
	if failure != nil {
		return nil, failure
	}
	if right.field.source != "" {
		return nil, mysqlCatalogUnsupported()
	}
	if like && p.keyword("ESCAPE") {
		// The reference consumes ESCAPE but applies the default escape rules.
		_, failure := p.atom()
		if failure != nil {
			return nil, failure
		}
	}
	var regex *regexp.Regexp
	var err error
	if like {
		regex, err = mysqlLikePattern(right.literal)
	} else {
		regex, err = regexp.Compile(right.literal)
	}
	return func(row mysqlCatalogRecord) mysqlTruth {
		value, present := left.value(row)
		_, hasPattern := right.value(row)
		if !present || !hasPattern {
			return mysqlUnknown
		}
		if err != nil {
			p.failure = &mysqlMetadataError{1105, "Invalid regular expression: " + err.Error()}
			return mysqlUnknown
		}
		return mysqlBoolean(regex.MatchString(value))
	}, nil
}

func (p *mysqlWhereParser) atom() (mysqlCatalogueJoinOperand, *mysqlMetadataError) {
	if p.terms >= mysqlMaxProjections {
		return mysqlCatalogueJoinOperand{}, mysqlCatalogUnsupported()
	}
	rest := strings.TrimSpace(p.rest)
	raw := mysqlWhereOperand.FindString(rest)
	if raw == "" {
		return mysqlCatalogueJoinOperand{}, mysqlCatalogUnsupported()
	}
	p.terms++
	p.rest = rest[len(raw):]
	if match := mysqlCatalogAggregateExpression.FindStringSubmatch(raw); match != nil {
		if field, ok := p.source.aggregateFields[mysqlCatalogAggregateKey(match)]; ok {
			return mysqlCatalogueJoinOperand{field: field, numeric: field.numeric()}, nil
		}
		return mysqlCatalogueJoinOperand{}, mysqlCatalogColumnError(raw)
	}
	if strings.EqualFold(raw, "TRUE") {
		return mysqlCatalogueJoinOperand{literal: "1", present: true, numeric: true}, nil
	}
	if strings.EqualFold(raw, "FALSE") {
		return mysqlCatalogueJoinOperand{literal: "0", present: true, numeric: true}, nil
	}
	if raw == "?" && p.bindings != nil && p.bindings.unbound && !p.bindings.preparing {
		position := p.bindings.next
		_, _, failure := p.bindings.operand(raw, p.database)
		if p.bindings.next == position {
			return mysqlCatalogueJoinOperand{}, failure
		}
		return mysqlCatalogueJoinOperand{read: func() (string, bool) {
			if p.failure == nil {
				p.failure = failure
			}
			return "", false
		}}, nil
	}
	return p.operand(raw)
}

func (p *mysqlWhereParser) scalar(precedence int) (mysqlWhereValue, *mysqlMetadataError) {
	left, failure := p.scalarAtom()
	for failure == nil {
		rest := strings.TrimSpace(p.rest)
		if rest == "" {
			break
		}
		op, strength := rest[0], 0
		switch op {
		case '+', '-':
			strength = 1
		case '*', '/', '%':
			strength = 2
		}
		if strength < precedence {
			break
		}
		p.rest = rest[1:]
		right, err := p.scalar(strength + 1)
		if err != nil {
			return mysqlWhereValue{}, err
		}
		previous := left
		left = mysqlWhereValue{numeric: true, value: func(row mysqlCatalogRecord) (string, bool) {
			a, hasA := previous.value(row)
			b, hasB := right.value(row)
			if !hasA || !hasB {
				return "", false
			}
			x, err := strconv.ParseFloat(a, 64)
			if err != nil {
				p.failure = &mysqlMetadataError{1105, fmt.Sprintf("error: '%s' is not a valid value for 'DOUBLE'", a)}
				return "", false
			}
			y, err := strconv.ParseFloat(b, 64)
			if err != nil {
				p.failure = &mysqlMetadataError{1105, fmt.Sprintf("error: '%s' is not a valid value for 'DOUBLE'", b)}
				return "", false
			}
			var result float64
			switch op {
			case '+':
				result = x + y
			case '-':
				result = x - y
			case '*':
				result = x * y
			case '/':
				result = x / y
			case '%':
				result = math.Mod(x, y)
			}
			return strconv.FormatFloat(result, 'f', -1, 64), !math.IsNaN(result) && !math.IsInf(result, 0)
		}}
	}
	return left, failure
}

func (p *mysqlWhereParser) scalarAtom() (mysqlWhereValue, *mysqlMetadataError) {
	if query, rest, ok := mysqlCatalogSplitGroup(p.rest); ok && mysqlCatalogSelectStart.MatchString(query) {
		p.rest = rest
		result, failure := p.singleColumnSubquery(query)
		if failure != nil {
			return mysqlWhereValue{}, failure
		}
		return mysqlWhereValue{numeric: result.numeric, value: func(row mysqlCatalogRecord) (string, bool) {
			values, failure := result.read(row)
			if failure != nil {
				p.failure = failure
				return "", false
			}
			switch len(values) {
			case 1:
				return values[0].value(row)
			case 0:
			default:
				p.failure = &mysqlMetadataError{1242, "the subquery returned more than 1 row"}
			}
			return "", false
		}}, nil
	}
	atom, failure := p.atom()
	return mysqlWhereValue{value: atom.value, numeric: atom.numeric}, failure
}

func mysqlWhereTruth(value mysqlWhereValue, row mysqlCatalogRecord) mysqlTruth {
	text, present := value.value(row)
	if !present {
		return mysqlUnknown
	}
	number, _ := strconv.ParseFloat(text, 64)
	return mysqlBoolean(number != 0)
}

func mysqlWhereCompare(row mysqlCatalogRecord, left mysqlWhereValue, op string, right mysqlWhereValue, numeric bool) mysqlTruth {
	a, hasA := left.value(row)
	b, hasB := right.value(row)
	if !hasA || !hasB {
		if op == "<=>" {
			return mysqlBoolean(!hasA && !hasB)
		}
		return mysqlUnknown
	}
	order := strings.Compare(a, b)
	if numeric {
		var valid bool
		order, valid = mysqlCatalogueNumericOrder(a, b)
		if !valid {
			// Numeric comparison coerces non-numeric text to zero.
			x, _ := strconv.ParseFloat(a, 64)
			y, _ := strconv.ParseFloat(b, 64)
			order = cmp.Compare(x, y)
		}
	}
	switch op {
	case "=", "<=>":
		return mysqlBoolean(order == 0)
	case "!=", "<>":
		return mysqlBoolean(order != 0)
	case "<":
		return mysqlBoolean(order < 0)
	case "<=":
		return mysqlBoolean(order <= 0)
	case ">":
		return mysqlBoolean(order > 0)
	case ">=":
		return mysqlBoolean(order >= 0)
	}
	return mysqlUnknown
}
