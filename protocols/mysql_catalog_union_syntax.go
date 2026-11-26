package protocols

import (
	"fmt"
	"regexp"
	"strings"
)

var mysqlUnionSyntaxToken = regexp.MustCompile(
	"(?is)'(?:[^'\\\\]|\\\\.|'')*'|\"(?:[^\"\\\\]|\\\\.|\"\")*\"|`(?:[^`]|``)*`|" +
		`0x[0-9a-f]+|(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?|\w+|<=>|<=|>=|<>|!=|[^\s]`)
var mysqlUnionLimitOperand = regexp.MustCompile(`^\d+$`)

type mysqlUnionSyntaxPart struct {
	text string
	end  int
}

func mysqlUnionSyntaxParts(raw string, offset int) []mysqlUnionSyntaxPart {
	var parts []mysqlUnionSyntaxPart
	for _, token := range mysqlUnionSyntaxToken.FindAllStringIndex(raw, -1) {
		parts = append(parts, mysqlUnionSyntaxPart{raw[token[0]:token[1]], offset + token[1]})
	}
	return parts
}

func mysqlUnionSyntaxAt(parts []mysqlUnionSyntaxPart, index, end int, fallback string) *mysqlMetadataError {
	position := end + 1
	if index < len(parts) {
		part := parts[index]
		position = part.end + 1
		if !mysqlUnionSyntaxPunctuation(part.text) {
			return mysqlUnionSyntaxError(position, mysqlUnquoteProjection(part.text))
		}
	}
	for i := index - 1; i >= 0; i-- {
		if text := parts[i].text; !mysqlUnionSyntaxPunctuation(text) {
			return mysqlUnionSyntaxError(position, mysqlUnquoteProjection(text))
		}
	}
	return mysqlUnionSyntaxError(position, fallback)
}

func mysqlUnionSyntaxError(position int, near string) *mysqlMetadataError {
	return &mysqlMetadataError{1105, fmt.Sprintf("syntax error at position %d near '%s'", position, near)}
}

func mysqlUnionSyntaxPunctuation(raw string) bool {
	return len(raw) == 1 && strings.ContainsRune("(),.;+-*/%=<>!&|^~", rune(raw[0]))
}

func mysqlUnionSyntaxBranch(query string, start, end int) *mysqlMetadataError {
	raw := query[start:end]
	if strings.TrimSpace(raw) == "" {
		prefix := mysqlUnionSyntaxParts(query[:start], 0)
		return mysqlUnionSyntaxAt(prefix, len(prefix), len(query), "")
	}
	parts := mysqlUnionSyntaxParts(raw, start)
	first := 0
	for first < len(parts) && parts[first].text == "(" {
		first++
	}
	if first == len(parts) || !strings.EqualFold(parts[first].text, "SELECT") {
		return mysqlUnionSyntaxAt(parts, first, end, "")
	}
	if first+1 == len(parts) || parts[first+1].text == ")" {
		return mysqlUnionSyntaxAt(parts, first+1, end, "")
	}
	if first > 0 {
		return mysqlUnionMemberTail(parts, first)
	}
	return nil
}

func mysqlUnionMemberTail(parts []mysqlUnionSyntaxPart, selectIndex int) *mysqlMetadataError {
	depth, tail := 0, -1
	for i := selectIndex + 1; i < len(parts); i++ {
		word := strings.ToUpper(parts[i].text)
		if word == ")" && depth == 0 {
			if tail >= 0 {
				return mysqlUnionSyntaxTail(parts[tail:i], parts[i].end)
			}
			break
		}
		if depth == 0 {
			if word == "UNION" {
				return nil
			}
			if tail < 0 && (word == "LIMIT" || word == "ORDER" && i+1 < len(parts) && strings.EqualFold(parts[i+1].text, "BY")) {
				tail = i
			}
		}
		switch word {
		case "(":
			depth++
		case ")":
			depth--
		}
	}
	return nil
}

func mysqlUnionSyntaxTail(parts []mysqlUnionSyntaxPart, end int) *mysqlMetadataError {
	limit := 0
	if strings.EqualFold(parts[0].text, "ORDER") {
		var failure *mysqlMetadataError
		limit, failure = mysqlUnionOrderEnd(parts, end)
		if failure != nil {
			return failure
		}
	}
	if limit == len(parts) {
		return nil
	}
	next := limit + 1
	for operands := 0; ; operands++ {
		if next == len(parts) || parts[next].text != "?" && !mysqlUnionLimitOperand.MatchString(parts[next].text) {
			return mysqlUnionSyntaxAt(parts, next, end, "LIMIT")
		}
		next++
		if next == len(parts) {
			return nil
		}
		if operands != 0 || parts[next].text != "," && !strings.EqualFold(parts[next].text, "OFFSET") {
			return mysqlUnionSyntaxAt(parts, next, end, "LIMIT")
		}
		next++
	}
}

func mysqlUnionOrderEnd(parts []mysqlUnionSyntaxPart, end int) (int, *mysqlMetadataError) {
	// ORDER BY is recognized before calling this function. Check list boundaries
	// without resolving the expressions, which the reference never evaluates.
	depth, start := 0, 2
	for i := start; i < len(parts); i++ {
		word := strings.ToUpper(parts[i].text)
		switch word {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth != 0 {
			continue
		}
		switch word {
		case ",", "LIMIT":
			if i == start || mysqlUnionOrderDangling(parts[i-1].text) {
				return i, mysqlUnionSyntaxAt(parts, i, end, "")
			}
			if word == "LIMIT" {
				return i, nil
			}
			start = i + 1
		case "ORDER":
			return i, mysqlUnionSyntaxAt(parts, i, end, "")
		case "ASC", "DESC":
			if i == start || mysqlUnionOrderDangling(parts[i-1].text) {
				return i, mysqlUnionSyntaxAt(parts, i, end, "")
			}
			if i+1 < len(parts) && parts[i+1].text != "," && !strings.EqualFold(parts[i+1].text, "LIMIT") {
				return i + 1, mysqlUnionSyntaxAt(parts, i+1, end, "")
			}
		}
	}
	if start == len(parts) || mysqlUnionOrderDangling(parts[len(parts)-1].text) {
		return len(parts), mysqlUnionSyntaxAt(parts, len(parts), end, "")
	}
	return len(parts), nil
}

func mysqlUnionOrderDangling(raw string) bool {
	return mysqlUnionSyntaxPunctuation(raw) && raw != ")"
}

func mysqlUnionWrappedSyntax(query string) *mysqlMetadataError {
	if !strings.HasPrefix(query, "(") {
		return nil
	}
	inner := strings.TrimLeft(query, "( \t\r\n")
	if !mysqlCatalogSelectStart.MatchString(inner) {
		return nil
	}
	if _, rest, grouped := mysqlCatalogSplitGroup(query); grouped && strings.TrimSpace(rest) != "" {
		offset := len(query) - len(rest)
		return mysqlUnionSyntaxAt(mysqlUnionSyntaxParts(rest, offset), 0, len(query), "")
	}
	parts := mysqlUnionSyntaxParts(query, 0)
	return mysqlUnionSyntaxAt(parts, len(parts), len(query), "")
}
