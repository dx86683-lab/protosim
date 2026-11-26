package protocols

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

func TestReferenceMySQLQueries(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	params := map[string]any{
		"accounts": []any{"fixture:lab-only"}, "db_name": "fixturedb", "table_name": "fixturetable",
	}
	handler := GetProtocol("mysql").HandleFunc.(func(*SessionConnection) error)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handler(&SessionConnection{Conn: conn, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: params}}})
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	open := func(password, database string) *sql.DB {
		t.Helper()
		cfg := mysql.NewConfig()
		cfg.Net, cfg.Addr, cfg.User, cfg.Passwd, cfg.DBName = "tcp", listener.Addr().String(), "fixture", password, database
		cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = time.Second, time.Second, time.Second
		connector, err := mysql.NewConnector(cfg)
		if err != nil {
			t.Fatal(err)
		}
		db := sql.OpenDB(connector)
		t.Cleanup(func() { db.Close() })
		return db
	}
	for _, tc := range []struct {
		password, database string
		code               uint16
	}{{"wrong", "fixturedb", 1045}, {"lab-only", "missing", 1105}} {
		var mysqlError *mysql.MySQLError
		if err := open(tc.password, tc.database).PingContext(ctx); !errors.As(err, &mysqlError) || mysqlError.Number != tc.code {
			t.Fatalf("database %s: error %v, want code %d", tc.database, err, tc.code)
		}
	}
	db := open("lab-only", "fixturedb")
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][2]string{
		{"SELECT 42 AS n", "42"}, {"SELECT 'hello'", "hello"},
		{"SELECT DATABASE()", "fixturedb"}, {"SHOW TABLES", "fixturetable"},
		{"SHOW TABLES IN `fixturedb` LIKE 'fixture%'", "fixturetable"},
		{"SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE()", "fixturetable"},
		{"SELECT COUNT(*) FROM information_schema.columns", "282"},
		{"SELECT ENGINE FROM information_schema.engines WHERE SUPPORT='DEFAULT'", "InnoDB"},
		{"SELECT c.COLUMN_NAME FROM information_schema.tables t JOIN information_schema.columns c " +
			"ON t.TABLE_SCHEMA=c.TABLE_SCHEMA AND t.TABLE_NAME=c.TABLE_NAME WHERE t.TABLE_SCHEMA=DATABASE() ORDER BY c.ORDINAL_POSITION LIMIT 1", "name"},
		{"SELECT COUNT(*) FROM information_schema.columns a JOIN information_schema.columns b " +
			"ON a.TABLE_CATALOG=b.TABLE_CATALOG", "79524"},
		{"SELECT COUNT(*) FROM information_schema.schemata a CROSS JOIN information_schema.engines b", "2"},
		{"SELECT COUNT(*) FROM information_schema.schemata a JOIN information_schema.schemata b ON a.SCHEMA_NAME<b.SCHEMA_NAME", "1"},
		{"SELECT c.COLUMN_NAME FROM information_schema.schemata s " +
			"JOIN information_schema.tables t ON s.SCHEMA_NAME=t.TABLE_SCHEMA " +
			"JOIN information_schema.columns c ON t.TABLE_NAME=c.TABLE_NAME AND t.TABLE_SCHEMA=c.TABLE_SCHEMA " +
			"WHERE s.SCHEMA_NAME='fixturedb' ORDER BY c.ORDINAL_POSITION LIMIT 1", "name"},
		{"SELECT COUNT(*) FROM information_schema.schemata a " +
			"JOIN information_schema.schemata b ON a.SCHEMA_NAME=b.SCHEMA_NAME " +
			"JOIN information_schema.schemata c ON a.SCHEMA_NAME=c.SCHEMA_NAME " +
			"JOIN information_schema.schemata d ON c.SCHEMA_NAME=d.SCHEMA_NAME", "2"},
		{"SELECT VERSION()", "8.0.11"},
	} {
		var got string
		if err := db.QueryRowContext(ctx, tc[0]).Scan(&got); err != nil || got != tc[1] {
			t.Fatalf("%s returned %q (%v), want %q", tc[0], got, err, tc[1])
		}
	}
	var named string
	if err := db.QueryRowContext(ctx, "SELECT d.named FROM (SELECT SCHEMA_NAME FROM information_schema.schemata WHERE SCHEMA_NAME='fixturedb') AS d(named)").
		Scan(&named); err != nil || named != "fixturedb" {
		t.Fatalf("renamed derived table returned %q (%v), want fixturedb", named, err)
	}
	const catalogueRightJoin = "SELECT b.SCHEMA_NAME FROM information_schema.schemata a " +
		"JOIN information_schema.schemata b ON a.SCHEMA_NAME=b.SCHEMA_NAME AND b.SCHEMA_NAME='fixturedb' " +
		"RIGHT JOIN information_schema.schemata c ON b.SCHEMA_NAME=c.SCHEMA_NAME"
	var padded sql.NullString
	if err := db.QueryRowContext(ctx, catalogueRightJoin+" ORDER BY c.SCHEMA_NAME LIMIT 1 OFFSET 1").
		Scan(&padded); err != nil || padded.Valid {
		t.Fatalf("right join without WHERE returned %v (%v), want NULL", padded, err)
	}
	if err := db.QueryRowContext(ctx, catalogueRightJoin+" WHERE c.SCHEMA_NAME='information_schema'").
		Scan(&padded); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("right join with WHERE returned %v (%v), want no rows", padded, err)
	}
	var mysqlUser, mysqlNow string
	var mysqlID uint32
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER(), NOW(), CONNECTION_ID() FROM information_schema.engines").
		Scan(&mysqlUser, &mysqlNow, &mysqlID); err != nil || !strings.HasPrefix(mysqlUser, "fixture@127.0.0.1:") || mysqlID == 0 {
		t.Fatalf("catalogue context returned user %q, time %q, connection %d (%v)", mysqlUser, mysqlNow, mysqlID, err)
	}
	if _, err := time.Parse("2006-01-02 15:04:05.999999", mysqlNow); err != nil {
		t.Fatalf("catalogue NOW() returned %q: %v", mysqlNow, err)
	}
	var groupName string
	var groupCount int
	if err := db.QueryRowContext(ctx, "SELECT TABLE_SCHEMA AS db, COUNT(*) AS n FROM information_schema.tables GROUP BY db HAVING n > ? ORDER BY n DESC",
		1).Scan(&groupName, &groupCount); err != nil || groupName != "information_schema" || groupCount != 20 {
		t.Fatalf("catalogue grouping returned %q, %d (%v), want information_schema, 20", groupName, groupCount, err)
	}
	var groupNames string
	if err := db.QueryRowContext(ctx, "SELECT GROUP_CONCAT(SCHEMA_NAME ORDER BY SCHEMA_NAME DESC SEPARATOR '|') FROM information_schema.schemata WHERE SCHEMA_NAME <> ?",
		"absent").Scan(&groupNames); err != nil || groupNames != "information_schema|fixturedb" {
		t.Fatalf("catalogue GROUP_CONCAT returned %q (%v), want information_schema|fixturedb", groupNames, err)
	}
	var unionName string
	var unionError *mysql.MySQLError
	if err := db.QueryRowContext(ctx, "SELECT SCHEMA_NAME AS db FROM information_schema.schemata WHERE SCHEMA_NAME=? UNION ALL SELECT ? ORDER BY db LIMIT ?",
		"fixturedb", "before").Scan(&unionName); !errors.As(err, &unionError) || unionError.Number != 1105 ||
		unionError.Message != `unbound variable "v1" in query` {
		t.Fatalf("prepared catalogue UNION returned %q (%v), want unbound v1", unionName, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT SCHEMA_NAME AS db FROM information_schema.schemata WHERE SCHEMA_NAME='fixturedb' UNION ALL SELECT 'before' ORDER BY db LIMIT 0").
		Scan(&unionName); err != nil || unionName != "fixturedb" {
		t.Fatalf("catalogue UNION returned %q (%v), want fixturedb", unionName, err)
	}
	for _, tc := range []struct{ query, diagnostic string }{
		{"SELECT 1 UNION ALL SELECT 2 LIMIT bad", "syntax error at position 38 near 'bad'"},
		{"(SELECT 1 AS x UNION ALL SELECT 2)", "syntax error at position 35 near '2'"},
	} {
		err := db.QueryRowContext(ctx, tc.query).Scan(&unionName)
		var syntax *mysql.MySQLError
		if !errors.As(err, &syntax) || syntax.Number != 1105 || syntax.Message != tc.diagnostic {
			t.Fatalf("%s returned %q (%v), want %s", tc.query, unionName, err, tc.diagnostic)
		}
	}
	for _, tc := range []struct{ query, value string }{
		{"SELECT SCHEMA_NAME FROM information_schema.schemata ORDER BY 1 DESC LIMIT 1", "information_schema"},
		{"SELECT 'text ORDER BY 1'", "text ORDER BY 1"},
	} {
		if err := db.QueryRowContext(ctx, tc.query).Scan(&unionName); err != nil || unionName != tc.value {
			t.Fatalf("%s returned %q (%v), want %q", tc.query, unionName, err, tc.value)
		}
	}
	for _, condition := range []string{"b.SCHEMA_NAME IS NULL", "b.SCHEMA_NAME <=> NULL"} {
		query := strings.Replace(catalogueRightJoin, "b.SCHEMA_NAME='fixturedb'", condition, 1)
		if err := db.QueryRowContext(ctx, query+" WHERE c.SCHEMA_NAME='information_schema'").
			Scan(&padded); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("right join with %s returned %v (%v), want no rows", condition, padded, err)
		}
	}
	const scalarCatalogue = "SELECT DATABASE() AS db, SCHEMA() AS s, VERSION() AS v, " +
		"-130 AS n, 'label' AS lbl, NULL AS missing FROM information_schema.schemata ORDER BY db LIMIT 1"
	var dbName, schemaName, serverVersion, label string
	var numberFromView int
	var missing sql.NullString
	if err := db.QueryRowContext(ctx, scalarCatalogue).
		Scan(&dbName, &schemaName, &serverVersion, &numberFromView, &label, &missing); err != nil ||
		dbName != "fixturedb" || schemaName != dbName || serverVersion != "8.0.11" || numberFromView != -130 || label != "label" || missing.Valid {
		t.Fatalf("catalogue scalars returned %q, %q, %q, %d, %q, %v (%v)", dbName, schemaName, serverVersion, numberFromView, label, missing, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT DATABASE(), -130 FROM information_schema.schemata WHERE SCHEMA_NAME=?",
		"fixturedb").Scan(&dbName, &numberFromView); err != nil || dbName != "fixturedb" || numberFromView != -130 {
		t.Fatalf("prepared catalogue scalars returned %q, %d (%v)", dbName, numberFromView, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.schemata WHERE NOT (SQL_PATH='x' AND FALSE)").
		Scan(&numberFromView); err != nil || numberFromView != 2 {
		t.Fatalf("catalogue three-valued WHERE returned %d (%v), want 2", numberFromView, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT ID FROM information_schema.collations WHERE (ID <= ? OR ID >= ?) AND ID <> ? ORDER BY ID LIMIT ?",
		2, 305, 1, 1).Scan(&numberFromView); err != nil || numberFromView != 2 {
		t.Fatalf("prepared catalogue WHERE returned %d (%v), want 2", numberFromView, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT d.db FROM (SELECT SCHEMA_NAME AS db FROM information_schema.schemata WHERE SCHEMA_NAME=?) d WHERE d.db=?",
		"fixturedb", "fixturedb").Scan(&dbName); err != nil || dbName != "fixturedb" {
		t.Fatalf("prepared catalogue derived table returned %q (%v)", dbName, err)
	}
	const subquery = "SELECT SCHEMA_NAME FROM information_schema.schemata WHERE SCHEMA_NAME NOT IN (SELECT SCHEMA_NAME FROM information_schema.schemata WHERE SCHEMA_NAME=%s)"
	if err := db.QueryRowContext(ctx, fmt.Sprintf(subquery, "'fixturedb'")).Scan(&dbName); err != nil || dbName != "information_schema" {
		t.Fatalf("catalogue IN subquery returned %q (%v)", dbName, err)
	}
	var bindError *mysql.MySQLError
	if err := db.QueryRowContext(ctx, fmt.Sprintf(subquery, "?"), "fixturedb").
		Scan(&dbName); !errors.As(err, &bindError) || bindError.Number != 1105 || bindError.Message != `unbound variable "v1" in query` {
		t.Fatalf("prepared catalogue IN subquery returned %q (%v), want unbound-variable error", dbName, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT a.SCHEMA_NAME FROM information_schema.schemata a WHERE a.SCHEMA_NAME IN (SELECT b.SCHEMA_NAME FROM information_schema.schemata b WHERE b.SCHEMA_NAME=a.SCHEMA_NAME AND b.SCHEMA_NAME='fixturedb')").
		Scan(&dbName); err != nil || dbName != "fixturedb" {
		t.Fatalf("correlated catalogue IN returned %q (%v), want fixturedb", dbName, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT a.SCHEMA_NAME FROM information_schema.schemata a WHERE a.SCHEMA_NAME IN (SELECT 'fixturedb' FROM information_schema.engines WHERE a.SCHEMA_NAME='information_schema')").
		Scan(&dbName); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("correlated catalogue filter returned %q (%v), want no rows", dbName, err)
	}
	for _, tc := range [][2]string{
		{"SELECT ENGINE FROM (SELECT ENGINE FROM information_schema.engines) WHERE ENGINE='InnoDB'",
			"Every derived table must have its own alias at position 73 near 'WHERE'"},
		{"SELECT a.ENGINE FROM (information_schema.engines AS a)",
			"unsupported syntax: (information_schema.`engines` as a)"},
	} {
		var diagnostic *mysql.MySQLError
		if err := db.QueryRowContext(ctx, tc[0]).Scan(&dbName); !errors.As(err, &diagnostic) ||
			diagnostic.Number != 1105 || diagnostic.Message != tc[1] {
			t.Fatalf("catalogue diagnostic for %q: got %v, want %q", tc[0], err, tc[1])
		}
	}
	var field, kind, nullable, key, def, extra string
	if err := db.QueryRowContext(ctx, "SHOW COLUMNS FROM fixturetable LIKE 'created_at'").
		Scan(&field, &kind, &nullable, &key, &def, &extra); err != nil ||
		field != "created_at" || kind != "timestamp" || nullable != "NO" || key != "" || def != "" || extra != "" {
		t.Fatalf("SHOW COLUMNS returned %q, %q, %q, %q, %q, %q (%v)", field, kind, nullable, key, def, extra, err)
	}
	var nameInDDL, ddl string
	if err := db.QueryRowContext(ctx, "SHOW CREATE TABLE fixturedb.fixturetable").Scan(&nameInDDL, &ddl); err != nil ||
		nameInDDL != "fixturetable" || !strings.HasPrefix(ddl, "CREATE TABLE `fixturetable` (\n  `name` text NOT NULL,") {
		t.Fatalf("SHOW CREATE TABLE returned %q, %q (%v)", nameInDDL, ddl, err)
	}
	indexes, err := db.QueryContext(ctx, "SHOW INDEX FROM fixturetable")
	if err != nil {
		t.Fatal(err)
	}
	defer indexes.Close()
	indexColumns, err := indexes.Columns()
	if err != nil || len(indexColumns) != 15 || indexColumns[0] != "Table" || indexColumns[14] != "Expression" || indexes.Next() || indexes.Err() != nil {
		t.Fatalf("SHOW INDEX returned columns %v, error %v, row error %v", indexColumns, err, indexes.Err())
	}
	metadata, err := db.PrepareContext(ctx, "SHOW CREATE TABLE fixturedb.fixturetable")
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	var preparedName, preparedDDL string
	if err := metadata.QueryRowContext(ctx).Scan(&preparedName, &preparedDDL); err != nil || preparedName != nameInDDL || preparedDDL != ddl {
		t.Fatalf("prepared SHOW CREATE TABLE returned %q, %q (%v)", preparedName, preparedDDL, err)
	}
	catalog, err := db.PrepareContext(ctx, "SELECT COLUMN_NAME, ORDINAL_POSITION FROM information_schema.columns WHERE TABLE_SCHEMA=? AND ORDINAL_POSITION=?")
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	var columnName string
	var position uint64
	if err := catalog.QueryRowContext(ctx, "fixturedb", 2).Scan(&columnName, &position); err != nil || columnName != "phone_numbers" || position != 2 {
		t.Fatalf("prepared catalogue query returned %q, %d (%v)", columnName, position, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_NAME LIKE ?", nil).
		Scan(&columnName); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("prepared catalogue LIKE with NULL returned %q (%v)", columnName, err)
	}
	var name, email, phone, created string
	if err := db.QueryRowContext(ctx, "SELECT * FROM fixturetable LIMIT 1").Scan(&name, &email, &phone, &created); err != nil {
		t.Fatal(err)
	}
	if name != "John Doe" || email != "john@doe.com" || phone != "555-555-555" || created == "" {
		t.Fatalf("unexpected fixture row: %q, %q, %q, %q", name, email, phone, created)
	}
	stmt, err := db.PrepareContext(ctx, "SELECT ? AS n")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	var number int64
	if err := stmt.QueryRowContext(ctx, int64(-42)).Scan(&number); err != nil || number != -42 {
		t.Fatalf("prepared integer = %v (%v)", number, err)
	}
	var value sql.NullString
	if err := stmt.QueryRowContext(ctx, "lab").Scan(&value); err != nil || !value.Valid || value.String != "lab" {
		t.Fatalf("prepared string = %v (%v)", value, err)
	}
	if err := stmt.QueryRowContext(ctx, nil).Scan(&value); err != nil || value.Valid {
		t.Fatalf("prepared NULL = %v (%v)", value, err)
	}
	var literal string
	if err := db.QueryRowContext(ctx, "SELECT 'a,b' AS literal, ? AS n, ? AS z", int64(19), nil).
		Scan(&literal, &number, &value); err != nil || literal != "a,b" || number != 19 || value.Valid {
		t.Fatalf("prepared projection = %q, %v, %v (%v)", literal, number, value, err)
	}
	var boolean bool
	var decimal float64
	if err := db.QueryRowContext(ctx, "SELECT NULL AS missing, ? AS `quoted, label`, FALSE hidden, -3.125 AS n", "lab").
		Scan(&value, &literal, &boolean, &decimal); err != nil || value.Valid || literal != "lab" || boolean || decimal != -3.125 {
		t.Fatalf("prepared mixed projection = %v, %q, %v, %v (%v)", value, literal, boolean, decimal, err)
	}
	connection, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var mode, zone string
	if err := connection.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode AS current_mode, @@time_zone").
		Scan(&mode, &zone); err != nil || mode != "NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES" || zone != "SYSTEM" {
		t.Fatalf("system variable projection = %q, %q (%v)", mode, zone, err)
	}
	if _, err := connection.ExecContext(ctx, "SET autocommit=0"); err != nil {
		t.Fatal(err)
	}
	var sessionAuto, globalAuto int
	if err := connection.QueryRowContext(ctx, "SELECT @@SESSION.autocommit, @@GLOBAL.autocommit").
		Scan(&sessionAuto, &globalAuto); err != nil || sessionAuto != 0 || globalAuto != 1 {
		t.Fatalf("autocommit projection = %d, %d (%v)", sessionAuto, globalAuto, err)
	}
	var variable, setting string
	if err := connection.QueryRowContext(ctx, "SHOW GLOBAL VARIABLES LIKE 'autocommit'").
		Scan(&variable, &setting); err != nil || variable != "autocommit" || setting != "0" {
		t.Fatalf("SHOW GLOBAL VARIABLES returned %q, %q (%v)", variable, setting, err)
	}
	readVariables, err := connection.PrepareContext(ctx, "SELECT @@SESSION.autocommit, @@GLOBAL.autocommit, @@SESSION.character_set_client")
	if err != nil {
		t.Fatal(err)
	}
	defer readVariables.Close()
	var charset string
	if err := readVariables.QueryRowContext(ctx).Scan(&sessionAuto, &globalAuto, &charset); err != nil || sessionAuto != 0 || globalAuto != 1 || charset != "utf8mb4" {
		t.Fatalf("initial prepared variables = %d, %d, %q (%v)", sessionAuto, globalAuto, charset, err)
	}
	for _, query := range []string{"SET autocommit=1", "SET NAMES latin1"} {
		if _, err := connection.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if err := readVariables.QueryRowContext(ctx).Scan(&sessionAuto, &globalAuto, &charset); err != nil || sessionAuto != 1 || globalAuto != 1 || charset != "latin1" {
		t.Fatalf("updated prepared variables = %d, %d, %q (%v)", sessionAuto, globalAuto, charset, err)
	}
	if _, err := connection.ExecContext(ctx, "SET SESSION wait_timeout=120, SESSION autocommit=OFF"); err != nil {
		t.Fatal(err)
	}
	var timeout, globalTimeout int
	if err := connection.QueryRowContext(ctx, "SELECT @@wait_timeout, @@GLOBAL.wait_timeout").Scan(&timeout, &globalTimeout); err != nil || timeout != 120 || globalTimeout != 28800 {
		t.Fatalf("scoped timeout = %d, %d (%v)", timeout, globalTimeout, err)
	}
	if err := readVariables.QueryRowContext(ctx).Scan(&sessionAuto, &globalAuto, &charset); err != nil || sessionAuto != 0 || globalAuto != 1 {
		t.Fatalf("prepared autocommit after scoped SET = %d, %d (%v)", sessionAuto, globalAuto, err)
	}
	if _, err := connection.ExecContext(ctx, "SET GLOBAL wait_timeout=240"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := connection.ExecContext(ctx, "SET GLOBAL wait_timeout=28800"); err != nil {
			t.Errorf("restore global wait_timeout: %v", err)
		}
	}()
	if err := connection.QueryRowContext(ctx, "SELECT @@wait_timeout, @@GLOBAL.wait_timeout").Scan(&timeout, &globalTimeout); err != nil || timeout != 120 || globalTimeout != 240 {
		t.Fatalf("existing connection after global SET = %d, %d (%v)", timeout, globalTimeout, err)
	}
	newDB := open("lab-only", "fixturedb")
	if err := newDB.QueryRowContext(ctx, "SELECT @@wait_timeout, @@GLOBAL.wait_timeout").Scan(&timeout, &globalTimeout); err != nil || timeout != 240 || globalTimeout != 240 {
		t.Fatalf("new connection after global SET = %d, %d (%v)", timeout, globalTimeout, err)
	}
}

func TestMySQLLengthEncodedParameterRequiresCompleteValue(t *testing.T) {
	for _, input := range [][]byte{
		{}, {0xfb}, {0xfc, 0x02, 0, 'a'}, {0xfd, 0x02, 0}, {0xfe, 0x01},
		{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 'a'},
	} {
		if _, consumed := mysqlLengthEncodedParameter(input); consumed != 0 {
			t.Errorf("incomplete length-encoded input %x consumed %d bytes", input, consumed)
		}
	}
	input := []byte{0xfe, 0x02, 0, 0, 0, 0, 0, 0, 0, 'a', 'b', 3}
	if value, consumed := mysqlLengthEncodedParameter(input); string(value) != "ab" || consumed != len(input)-1 {
		t.Fatalf("decoded %q with width %d", value, consumed)
	}
}

func TestMySQLStreamBudgetIsConnectionLocal(t *testing.T) {
	first := &mysqlStatement{parameters: make([]mysqlParameter, 1)}
	second := &mysqlStatement{parameters: make([]mysqlParameter, 1)}
	model := mysqlSimulation{statements: map[uint32]*mysqlStatement{1: first, 2: second}}
	chunk := make([]byte, 6+mysqlMaxStreamBytes/2)
	binary.LittleEndian.PutUint32(chunk, 1)
	if !model.addStream(chunk) || !model.addStream(chunk) {
		t.Fatal("valid chunks within the connection limit were rejected")
	}
	binary.LittleEndian.PutUint32(chunk, 2)
	if model.addStream(chunk) || second.parameters[0].stream != nil {
		t.Fatal("a second statement exceeded the shared stream limit")
	}
	model.discardStreams(first)
	if !model.addStream(chunk) || model.streamBytes != len(chunk)-6 {
		t.Fatal("discarding the first stream did not release its budget")
	}
}
