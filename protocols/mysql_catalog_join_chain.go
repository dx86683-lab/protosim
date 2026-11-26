package protocols

import (
	"regexp"
	"slices"
	"strings"
)

var mysqlCatalogChainPrefix = regexp.MustCompile(mysqlCatalogSelectPrefix)
var mysqlCatalogChainSource = regexp.MustCompile(`(?is)^\s*` + mysqlMetadataObject + mysqlCatalogAlias +
	`(?:\s+(ON|USING)\b\s*(.+))?\s*$`)
var mysqlCatalogChainTail = regexp.MustCompile(`(?is)^` + mysqlCatalogSelectTail)
var mysqlCatalogNestedSelect = regexp.MustCompile(`(?i)\(\s*SELECT\s+`)
var mysqlCatalogSelectStart = regexp.MustCompile(`(?i)^SELECT\s+`)
var mysqlCatalogDerivedAlias = regexp.MustCompile(`(?is)^\s*(?:AS\s+)?(` + mysqlMetadataName +
	`)(?:\s+(ON|USING)\b\s*(.+))?\s*$`)
var mysqlCatalogDerivedColumnList = regexp.MustCompile(`(?is)^\s*(?:AS\s+)?(` + mysqlMetadataName +
	`)\s*\(\s*((?:` + mysqlMetadataName + `)(?:\s*,\s*(?:` + mysqlMetadataName + `))*)\s*\)(?:\s+(ON|USING)\b\s*(.+))?\s*$`)
var mysqlCatalogChainBoundary = regexp.MustCompile(
	"(?is)'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`(?:[^`]|``)*`|[(),]|" +
		`\b(?:(` + mysqlCatalogJoinKind + `)|(WHERE|GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT))\b`)

type mysqlCatalogFromItem struct {
	raw, kind string
	offset    int
}

func mysqlCatalogScanSources(body string) ([]mysqlCatalogFromItem, int, bool) {
	start, end, depth := 0, len(body), 0
	kind := ""
	var items []mysqlCatalogFromItem
	for _, boundary := range mysqlCatalogChainBoundary.FindAllStringSubmatchIndex(body, -1) {
		token := body[boundary[0]:boundary[1]]
		switch token[0] {
		case '(':
			depth++
			continue
		case ')':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		if boundary[4] >= 0 {
			end = boundary[0]
			// Keep the leading space expected by the SELECT tail grammar.
			for end > start && strings.ContainsRune(" \t\r\n", rune(body[end-1])) {
				end--
			}
			break
		}
		if boundary[2] >= 0 || token == "," {
			items = append(items, mysqlCatalogFromItem{body[start:boundary[0]], kind, start})
			start, kind = boundary[1], token
		}
	}
	return append(items, mysqlCatalogFromItem{body[start:end], kind, start}), end, depth == 0
}

func mysqlCatalogJoinChain(query string, nested bool) (*mysqlCatalogJoinQuery, *mysqlMetadataError) {
	prefix := mysqlCatalogChainPrefix.FindStringSubmatch(query)
	if prefix == nil {
		return nil, nil
	}
	body := query[len(prefix[0]):]
	items, end, balanced := mysqlCatalogScanSources(body)
	if !balanced {
		return nil, nil
	}
	tail := mysqlCatalogJoinTail(body[end:])
	if tail == nil {
		return nil, nil
	}
	if !nested && len(items) < 3 && tail[1] == "" && tail[2] == "" && !mysqlCatalogNestedSelect.MatchString(body) &&
		!slices.ContainsFunc(items, func(item mysqlCatalogFromItem) bool { return strings.HasPrefix(strings.TrimSpace(item.raw), "(") }) {
		return nil, nil
	}
	result := &mysqlCatalogJoinQuery{distinct: prefix[1], projection: prefix[2], tail: tail}
	for _, item := range items {
		if inner, rest, ok := mysqlCatalogSplitGroup(item.raw); ok {
			if !mysqlCatalogSelectStart.MatchString(inner) {
				return nil, mysqlCatalogGroupedDiagnostic(query, item, len(prefix[0]), rest)
			}
			if alias := mysqlCatalogDerivedAlias.FindStringSubmatch(rest); alias != nil && !mysqlDiagnosticClause(alias[1]) {
				result.sources = append(result.sources, mysqlCatalogJoinSource{
					subquery: inner, alias: alias[1], kind: item.kind, clause: alias[2], condition: alias[3],
				})
				continue
			}
			if alias := mysqlCatalogDerivedColumnList.FindStringSubmatch(rest); alias != nil && !mysqlDiagnosticClause(alias[1]) {
				names := mysqlSplitExpressions(alias[2])
				if !slices.ContainsFunc(names, func(name string) bool {
					return mysqlDiagnosticClause(name) || strings.EqualFold(name, "FIRST")
				}) {
					for i := range names {
						names[i] = mysqlUnquoteProjection(names[i])
					}
					result.sources = append(result.sources, mysqlCatalogJoinSource{
						subquery: inner, alias: alias[1], columns: names, kind: item.kind, clause: alias[3], condition: alias[4],
					})
					continue
				}
			}
			return nil, mysqlCatalogDerivedDiagnostic(query, item, len(prefix[0]), inner, rest)
		}
		match := mysqlCatalogChainSource.FindStringSubmatch(item.raw)
		if match == nil {
			return nil, nil
		}
		result.sources = append(result.sources, mysqlCatalogJoinSource{
			database: match[1], table: match[2], alias: match[3], kind: item.kind, clause: match[4], condition: match[5],
		})
	}
	return result, nil
}

func mysqlCatalogSplitGroup(raw string) (inner, rest string, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "(") {
		return "", raw, false
	}
	depth := 0
	for _, token := range mysqlCatalogChainBoundary.FindAllStringIndex(raw, -1) {
		switch raw[token[0]] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(raw[1:token[0]]), raw[token[1]:], true
			}
		}
	}
	return "", raw, false
}

func mysqlCatalogJoinTail(raw string) []string {
	if mysqlCatalogNestedSelect.MatchString(raw) {
		depth, start := 0, -1
		for _, token := range mysqlCatalogChainBoundary.FindAllStringSubmatchIndex(raw, -1) {
			switch raw[token[0]] {
			case '(':
				depth++
			case ')':
				depth--
			default:
				if depth != 0 || token[4] < 0 {
					continue
				}
				if strings.EqualFold(raw[token[0]:token[1]], "WHERE") && start < 0 {
					start = token[1]
					continue
				}
				if start >= 0 {
					end := token[0]
					for end > start && strings.ContainsRune(" \t\r\n", rune(raw[end-1])) {
						end--
					}
					tail := mysqlCatalogChainTail.FindStringSubmatch(raw[end:])
					if tail == nil || tail[1] != "" {
						return nil
					}
					tail[1] = strings.TrimSpace(raw[start:end])
					return tail[1:]
				}
			}
		}
		if start >= 0 && depth == 0 {
			return []string{strings.TrimSpace(raw[start:]), "", "", "", "", "", ""}
		}
	}
	if tail := mysqlCatalogChainTail.FindStringSubmatch(raw); tail != nil {
		return tail[1:]
	}
	return nil
}
