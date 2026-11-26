package protocols

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var mysqlCatalogUnionTokens = regexp.MustCompile(
	"(?is)'(?:[^'\\\\]|\\\\.|'')*'|\"(?:[^\"\\\\]|\\\\.|\"\")*\"|`(?:[^`]|``)*`|[()]|" +
		`\b(?:(UNION)(?:\s+(ALL|DISTINCT)\b)?|(ORDER\s+BY|LIMIT)\b)\b`)

type mysqlCatalogUnionBranch struct {
	query    string
	distinct bool
}

func mysqlCatalogUnionBranches(query string) ([]mysqlCatalogUnionBranch, *mysqlMetadataError) {
	if !mysqlCatalogSelectStart.MatchString(query) && !strings.HasPrefix(query, "(") {
		return nil, nil
	}
	var branches []mysqlCatalogUnionBranch
	depth, start, tail, unexpectedClose := 0, 0, -1, -1
	distinct := false
	for _, token := range mysqlCatalogUnionTokens.FindAllStringSubmatchIndex(query, -1) {
		switch query[token[0]] {
		case '(':
			depth++
		case ')':
			if depth == 0 && unexpectedClose < 0 {
				unexpectedClose = token[0]
			}
			depth--
		}
		if depth != 0 {
			continue
		}
		if token[2] >= 0 {
			if tail >= 0 {
				return nil, mysqlDiagnosticAt(query, token[0], "syntax error", "")
			}
			if failure := mysqlUnionSyntaxBranch(query, start, token[0]); failure != nil {
				return nil, failure
			}
			branches = append(branches, mysqlCatalogUnionBranch{query[start:token[0]], distinct})
			if len(branches) >= mysqlMaxProjections {
				return nil, mysqlCatalogUnsupported()
			}
			start = token[1]
			distinct = token[4] < 0 || !strings.EqualFold(query[token[4]:token[5]], "ALL")
		} else if token[6] >= 0 && tail < 0 {
			tail = token[0]
		}
	}
	if len(branches) == 0 {
		return nil, mysqlUnionWrappedSyntax(query)
	}
	if unexpectedClose >= 0 {
		parts := mysqlUnionSyntaxParts(query[:unexpectedClose+1], 0)
		return nil, mysqlUnionSyntaxAt(parts, len(parts)-1, len(query), "")
	}
	if depth != 0 {
		parts := mysqlUnionSyntaxParts(query, 0)
		return nil, mysqlUnionSyntaxAt(parts, len(parts), len(query), "")
	}
	if tail < 0 {
		tail = len(query)
	}
	if failure := mysqlUnionSyntaxBranch(query, start, tail); failure != nil {
		return nil, failure
	}
	// The reference parses the set-level clauses without applying them.
	if tail < len(query) {
		if failure := mysqlUnionSyntaxTail(mysqlUnionSyntaxParts(query[tail:], tail), len(query)); failure != nil {
			return nil, failure
		}
	}
	return append(branches, mysqlCatalogUnionBranch{query[start:tail], distinct}), nil
}

func (m *mysqlSimulation) catalogUnion(branches []mysqlCatalogUnionBranch, bindings *mysqlCatalogBindings, depth int, outer *mysqlCatalogScope) (*mysqlCatalogResult, *mysqlMetadataError) {
	unionBindings := mysqlCatalogBindings{unbound: true}
	if bindings != nil {
		unionBindings = *bindings
		unionBindings.unbound = true
		defer func() { bindings.next = unionBindings.next }()
	}

	result := &mysqlCatalogResult{}
	members := make([]*mysqlCatalogResult, 0, len(branches))
	distinctEnd := 0
	for _, branch := range branches {
		query := strings.TrimSpace(branch.query)
		branchDepth := depth + 1
		for {
			inner, rest, grouped := mysqlCatalogSplitGroup(query)
			if !grouped || strings.TrimSpace(rest) != "" {
				break
			}
			query = inner
			branchDepth++
		}
		member, failure := m.catalogSubquery(query, &unionBindings, branchDepth, outer)
		if failure != nil {
			return nil, failure
		}
		if result.columns == nil {
			result.columns = append(result.columns, member.columns...)
			for i := range result.columns {
				result.columns[i].scalar, result.columns[i].aggregate = nil, nil
			}
		} else if len(result.columns) != len(member.columns) {
			return nil, &mysqlMetadataError{1105, fmt.Sprintf(
				"cannot union two queries whose schemas are different lengths; left has %d column(s) right has %d column(s).",
				len(result.columns), len(member.columns))}
		} else {
			for i, right := range member.columns {
				left := &result.columns[i]
				if left.kind != right.kind || left.charset != right.charset || left.flags != right.flags {
					left.kind, left.charset, left.flags = 0xfc, 33, 0
				}
			}
		}
		members = append(members, member)
	}
	for i, member := range members {
		result.rows = append(result.rows, mysqlUnionRows(member, result.columns)...)
		if branches[i].distinct {
			distinctEnd = len(result.rows)
		}
	}
	// The last DISTINCT removes duplicates from all branches to its left.
	if distinctEnd > 0 {
		seen := make(map[string]struct{}, distinctEnd)
		unique := result.rows[:0]
		for _, row := range result.rows[:distinctEnd] {
			key := string(row)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				unique = append(unique, row)
			}
		}
		result.rows = append(unique, result.rows[distinctEnd:]...)
	}
	return result, nil
}

func mysqlUnionRows(member *mysqlCatalogResult, columns []mysqlCatalogProjectionField) [][]byte {
	convertTimestamps := false
	for i, column := range member.columns {
		if column.kind == 7 && columns[i].kind != 7 {
			convertTimestamps = true
			break
		}
	}
	if !convertTimestamps {
		return member.rows
	}
	rows := make([][]byte, 0, len(member.rows))
	for _, packet := range member.rows {
		var row []byte
		for i, column := range member.columns {
			if packet[0] == 0xfb {
				row = append(row, packet[0])
				packet = packet[1:]
				continue
			}
			text, width := mysqlLengthEncodedParameter(packet)
			if column.kind == 7 && columns[i].kind != 7 {
				if stamp, err := time.Parse("2006-01-02 15:04:05", string(text)); err == nil {
					row = appendMySQLString(row, stamp.Local().Format("2006-01-02 15:04:05.999999"))
					packet = packet[width:]
					continue
				}
			}
			row = append(row, packet[:width]...)
			packet = packet[width:]
		}
		rows = append(rows, row)
	}
	return rows
}
