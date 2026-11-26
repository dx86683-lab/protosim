package protocols

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed fixtures/reference-mssql.json
var mssqlFixtures []byte

func TestReferenceMSSQLSessions(t *testing.T) {
	var cases []round6Case
	if err := json.Unmarshal(mssqlFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]round6Case, len(cases))
	for _, tc := range cases {
		byName[tc.Name] = tc
		t.Run(tc.Name, func(t *testing.T) { runRound6Case(t, tc) })
	}
	t.Run("SQL batch requires login", func(t *testing.T) {
		steps := byName["default"].Steps
		runRound6Case(t, round6Case{Handler: "mssql", Steps: []round6Step{
			steps[0], {Send: steps[2].Send, EOF: true},
		}})
	})
	t.Run("configured accounts take precedence", func(t *testing.T) {
		defaultSteps := byName["default"].SimSteps
		if len(defaultSteps) == 0 {
			defaultSteps = byName["default"].Steps
		}
		wrongSteps := byName["default-wrong"].SimSteps
		if len(wrongSteps) == 0 {
			wrongSteps = byName["default-wrong"].Steps
		}
		valid := defaultSteps[1]
		rejected := wrongSteps[1]
		configured := rejected
		configured.Recv = valid.Recv
		tc := round6Case{Handler: "mssql", Params: map[string]any{"accounts": []any{"sa:wrong"}}}
		tc.Steps = []round6Step{configured}
		runRound6Case(t, tc)

		valid.Recv = rejected.Recv
		tc.Steps = []round6Step{valid, {EOF: true}}
		runRound6Case(t, tc)

		tc.Params["accounts"] = []any{}
		runRound6Case(t, tc)
	})
}
