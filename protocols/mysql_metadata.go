package protocols

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const mysqlMetadataName = "(?:[a-z0-9_$]+|`(?:[^`]|``)+`)"
const mysqlMetadataObject = `(` + mysqlMetadataName + `)(?:\s*\.\s*(` + mysqlMetadataName + `))?`
const mysqlMetadataLike = `(?:\s+LIKE\s+('(?:[^']|'')*'|"(?:[^"]|"")*"))?`

var mysqlShowTables = regexp.MustCompile(`(?i)^SHOW\s+(?:(FULL)\s+)?TABLES(?:\s+(?:FROM|IN)\s+(` + mysqlMetadataName + `))?` + mysqlMetadataLike + `$`)
var mysqlShowColumns = regexp.MustCompile(`(?i)^SHOW\s+(?:(FULL)\s+)?(?:COLUMNS|FIELDS)\s+FROM\s+` + mysqlMetadataObject + `(?:\s+(?:FROM|IN)\s+` + mysqlMetadataName + `)?` + mysqlMetadataLike + `$`)
var mysqlDescribeTable = regexp.MustCompile(`(?i)^(?:DESCRIBE|DESC)\s+` + mysqlMetadataObject + `$`)
var mysqlShowDatabases = regexp.MustCompile(`(?i)^SHOW\s+(?:DATABASES|SCHEMAS)` + mysqlMetadataLike + `$`)
var mysqlShowIndex = regexp.MustCompile(`(?is)^SHOW\s+(?:INDEX|INDEXES|KEYS)\s+(?:FROM|IN)\s+` + mysqlMetadataObject + `(?:\s+(?:FROM|IN)\s+(` + mysqlMetadataName + `))?(?:\s+WHERE\s+.+)?$`)
var mysqlShowCreateTable = regexp.MustCompile(`(?i)^SHOW\s+CREATE\s+TABLE\s+` + mysqlMetadataObject + `$`)
var mysqlShowCreateDatabase = regexp.MustCompile(`(?i)^SHOW\s+CREATE\s+(?:DATABASE|SCHEMA)\s+(?:(IF\s+NOT\s+EXISTS)\s+)?(` + mysqlMetadataName + `)$`)
var mysqlMetadataParameter = regexp.MustCompile(`(?i)^SHOW\s+(?:(?:FULL|GLOBAL|SESSION)\s+)?(?:TABLES|DATABASES|SCHEMAS|COLUMNS|FIELDS|VARIABLES)\b.*\sLIKE\s+\?$`)

type mysqlMetadataResult struct {
	columns           []mysqlColumn
	textRows          [][]byte
	usePreviousStatus bool
}

type mysqlMetadataError struct {
	code    uint16
	message string
}

func (m *mysqlSimulation) schemaMetadata(query string) (*mysqlMetadataResult, *mysqlMetadataError) {
	if match := mysqlShowTables.FindStringSubmatch(query); match != nil {
		return m.showTables(match[1] != "", mysqlUnquoteProjection(match[2]), match[3])
	}
	if match := mysqlShowColumns.FindStringSubmatch(query); match != nil {
		return m.showColumns(match[1] != "", match[2], match[3], match[4])
	}
	if match := mysqlDescribeTable.FindStringSubmatch(query); match != nil {
		return m.showColumns(false, match[1], match[2], "")
	}
	if match := mysqlShowIndex.FindStringSubmatch(query); match != nil {
		return m.showIndex(match[1], match[2], mysqlUnquoteProjection(match[3]))
	}
	if match := mysqlShowCreateTable.FindStringSubmatch(query); match != nil {
		return m.showCreateTable(match[1], match[2])
	}
	if match := mysqlShowCreateDatabase.FindStringSubmatch(query); match != nil {
		return m.showCreateDatabase(mysqlUnquoteProjection(match[2]), match[1] != "")
	}
	if mysqlShowDatabases.MatchString(query) {
		// The reference accepts LIKE and returns the whole inventory.
		return &mysqlMetadataResult{
			columns:  []mysqlColumn{{"Database", 0xfc}},
			textRows: mysqlTextRows([][]string{{m.schema}, {"information_schema"}}),
		}, nil
	}
	return nil, nil
}

func (m *mysqlSimulation) preparedMetadata(query string) (*mysqlMetadataResult, *mysqlMetadataError) {
	if result, failure := m.schemaMetadata(query); result != nil || failure != nil {
		return result, failure
	}
	if match := mysqlShowVariables.FindStringSubmatch(query); match != nil {
		rows, err := m.systemVariableRows(match[1])
		if err != nil {
			return nil, &mysqlMetadataError{1105, "query not supported by simulator"}
		}
		return &mysqlMetadataResult{
			columns: mysqlVariableColumns, textRows: mysqlTextRows(rows), usePreviousStatus: match[1] == "",
		}, nil
	}
	if mysqlMetadataParameter.MatchString(query) {
		return nil, &mysqlMetadataError{1105, fmt.Sprintf("syntax error at position %d near ':v1'", len(query)+1)}
	}
	return nil, nil
}

func (r *mysqlMetadataResult) binaryRows() [][]byte {
	rows := make([][]byte, 0, len(r.textRows))
	for _, text := range r.textRows {
		row := make([]byte, 1+(len(r.columns)+9)/8)
		for i := range r.columns {
			if text[0] == 0xfb {
				row[1+(i+2)/8] |= 1 << ((i + 2) % 8)
				text = text[1:]
			} else {
				// Metadata values are strings encoded by appendMySQLString.
				_, width := mysqlLengthEncodedParameter(text)
				row = append(row, text[:width]...)
				text = text[width:]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

type mysqlMetadataColumn struct {
	Name     string
	Type     string
	Nullable bool
	Default  string
}

//go:embed fixtures/mysql-information-schema.json
var mysqlInformationSchemaJSON []byte

var mysqlInformationSchema = func() map[string][]mysqlMetadataColumn {
	var tables map[string][]mysqlMetadataColumn
	if err := json.Unmarshal(mysqlInformationSchemaJSON, &tables); err != nil {
		panic(err)
	}
	return tables
}()

var mysqlInfoTables = slices.Sorted(maps.Keys(mysqlInformationSchema))

var mysqlIndexColumns = []mysqlColumn{
	{"Table", 0xfc}, {"Non_unique", 3}, {"Key_name", 0xfc}, {"Seq_in_index", 3}, {"Column_name", 0xfc},
	{"Collation", 0xfc}, {"Cardinality", 8}, {"Sub_part", 8}, {"Packed", 0xfc}, {"Null", 0xfc},
	{"Index_type", 0xfc}, {"Comment", 0xfc}, {"Index_comment", 0xfc}, {"Visible", 0xfc}, {"Expression", 0xfc},
}

func mysqlMetadataPattern(filter string) (*regexp.Regexp, error) {
	// The SQL string parser removes one level of backslash escaping before LIKE.
	return mysqlLikePattern(strings.ReplaceAll(mysqlUnquoteProjection(filter), `\\`, `\`))
}

func (m *mysqlSimulation) showTables(full bool, database, filter string) (*mysqlMetadataResult, *mysqlMetadataError) {
	if database == "" {
		database = m.current
	}
	var tables []string
	switch {
	case database == "":
		return nil, &mysqlMetadataError{1105, "plan is not resolved because of node '*plan.ShowTables'"}
	case strings.EqualFold(database, "information_schema"):
		tables = mysqlInfoTables
	case strings.EqualFold(database, m.schema):
		tables = []string{m.table}
	default:
		return nil, &mysqlMetadataError{1105, "database not found: " + database}
	}
	pattern, err := mysqlMetadataPattern(filter)
	if err != nil {
		return nil, &mysqlMetadataError{1105, err.Error()}
	}
	columns := []mysqlColumn{{"Table", 0xfc}}
	if full {
		columns = append(columns, mysqlColumn{"Table_type", 0xfc})
	}
	rows := make([][]string, 0, len(tables))
	for _, table := range tables {
		if filter != "" && !pattern.MatchString(table) {
			continue
		}
		row := []string{table}
		if full {
			row = append(row, "BASE TABLE")
		}
		rows = append(rows, row)
	}
	return &mysqlMetadataResult{columns: columns, textRows: mysqlTextRows(rows)}, nil
}

func (m *mysqlSimulation) showColumns(full bool, object, qualified, filter string) (*mysqlMetadataResult, *mysqlMetadataError) {
	// The reference uses the current database for an unqualified table, even
	// when SHOW COLUMNS includes a trailing FROM or IN database clause.
	database, table := m.metadataObject(object, qualified)
	_, metadata, failure := m.metadataTable(database, table)
	if failure != nil {
		return nil, failure
	}
	pattern, err := mysqlMetadataPattern(filter)
	if err != nil {
		return nil, &mysqlMetadataError{1105, err.Error()}
	}
	fields := []string{"Field", "Type", "Null", "Key", "Default", "Extra"}
	if full {
		fields = []string{"Field", "Type", "Collation", "Null", "Key", "Default", "Extra", "Privileges", "Comment"}
	}
	columns := make([]mysqlColumn, 0, len(fields))
	for _, field := range fields {
		columns = append(columns, mysqlColumn{field, 0xfc})
	}
	var rows [][]byte
	for _, column := range metadata {
		if filter != "" && !pattern.MatchString(column.Name) {
			continue
		}
		row := appendMySQLString(appendMySQLString(nil, column.Name), column.Type)
		if full {
			if column.Type == "text" || column.Type == "longtext" || strings.HasPrefix(column.Type, "varchar(") {
				row = appendMySQLString(row, "utf8mb4_0900_bin")
			} else {
				row = append(row, 0xfb) // SQL NULL for a non-text collation.
			}
		}
		nullable := "NO"
		if column.Nullable {
			nullable = "YES"
		}
		for _, field := range []string{nullable, "", column.Default, ""} {
			row = appendMySQLString(row, field)
		}
		if full {
			row = append(row, 0, 0) // Empty Privileges and Comment.
		}
		rows = append(rows, row)
	}
	return &mysqlMetadataResult{columns: columns, textRows: rows}, nil
}

func (m *mysqlSimulation) metadataObject(object, qualified string) (database, table string) {
	if qualified == "" {
		return m.current, mysqlUnquoteProjection(object)
	}
	return mysqlUnquoteProjection(object), mysqlUnquoteProjection(qualified)
}

func (m *mysqlSimulation) metadataDatabase(name string) string {
	switch {
	case strings.EqualFold(name, "information_schema"):
		return "information_schema"
	case strings.EqualFold(name, m.schema):
		return m.schema
	default:
		return ""
	}
}

func (m *mysqlSimulation) metadataTable(database, table string) (string, []mysqlMetadataColumn, *mysqlMetadataError) {
	if database == "" {
		return "", nil, &mysqlMetadataError{1105, "no database selected"}
	}
	switch m.metadataDatabase(database) {
	case "":
		return "", nil, &mysqlMetadataError{1105, "database not found: " + database}
	case "information_schema":
		name := strings.ToLower(table)
		if columns, ok := mysqlInformationSchema[name]; ok {
			return name, columns, nil
		}
	default:
		if strings.EqualFold(table, m.table) {
			columns := make([]mysqlMetadataColumn, 0, len(mysqlUserColumns))
			for _, column := range mysqlUserColumns {
				kind := "text"
				if column.kind == 7 {
					kind = "timestamp"
				}
				columns = append(columns, mysqlMetadataColumn{Name: column.name, Type: kind})
			}
			return m.table, columns, nil
		}
	}
	return "", nil, &mysqlMetadataError{1146, "table not found: " + table}
}

func (m *mysqlSimulation) showIndex(object, qualified, database string) (*mysqlMetadataResult, *mysqlMetadataError) {
	// Index lookup uses the trailing database clause or the current database.
	// A database prefix on the table and a WHERE clause do not filter the result.
	if database == "" {
		database = m.current
	}
	if qualified != "" {
		object = qualified
	}
	if _, _, failure := m.metadataTable(database, mysqlUnquoteProjection(object)); failure != nil {
		return nil, failure
	}
	return &mysqlMetadataResult{columns: mysqlIndexColumns}, nil
}

func mysqlQuoteMetadataName(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func (m *mysqlSimulation) showCreateTable(object, qualified string) (*mysqlMetadataResult, *mysqlMetadataError) {
	database, table := m.metadataObject(object, qualified)
	name, metadata, failure := m.metadataTable(database, table)
	if failure != nil {
		return nil, failure
	}
	definitions := make([]string, 0, len(metadata))
	for _, column := range metadata {
		definition := "  " + mysqlQuoteMetadataName(column.Name) + " " + column.Type
		if !column.Nullable {
			definition += " NOT NULL"
		}
		if column.Default != "" {
			definition += " DEFAULT " + column.Default
		}
		definitions = append(definitions, definition)
	}
	ddl := "CREATE TABLE " + mysqlQuoteMetadataName(name) + " (\n" + strings.Join(definitions, ",\n") + "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
	return &mysqlMetadataResult{
		columns:  []mysqlColumn{{"Table", 0xfc}, {"Create Table", 0xfc}},
		textRows: mysqlTextRows([][]string{{name, ddl}}),
	}, nil
}

func (m *mysqlSimulation) showCreateDatabase(database string, ifNotExists bool) (*mysqlMetadataResult, *mysqlMetadataError) {
	name := m.metadataDatabase(database)
	if name == "" {
		return nil, &mysqlMetadataError{1105, "database not found: " + database}
	}
	ddl := "CREATE DATABASE "
	if ifNotExists {
		ddl += "/*!32312 IF NOT EXISTS*/ "
	}
	ddl += mysqlQuoteMetadataName(name) + " /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin */"
	return &mysqlMetadataResult{
		columns:  []mysqlColumn{{"Database", 0xfc}, {"Create Database", 0xfc}},
		textRows: mysqlTextRows([][]string{{name, ddl}}),
	}, nil
}
