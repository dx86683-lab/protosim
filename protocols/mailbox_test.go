package protocols

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

//go:embed fixtures/reference-mailbox.json
var referenceMailbox []byte

func TestReferencePOP3GreetingArmsSixtySecondDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deadlines := make(chan time.Time, 1)
	started := time.Now()
	go servePOP3(&SessionConnection{
		Conn:       observedDeadlineConn{Conn: server, deadline: deadlines},
		ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}},
	})
	const banner = "+OK Dovecot ready\r\n"
	reply := make([]byte, len(banner))
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != banner {
		t.Fatalf("greeting = %q (%v), want %q", reply, err, banner)
	}
	select {
	case deadline := <-deadlines:
		earliest := started.Add(time.Minute)
		latest := time.Now().Add(time.Minute)
		if deadline.Before(earliest) || deadline.After(latest) {
			t.Fatalf("POP3 deadline = %v, want between %v and %v", deadline, earliest, latest)
		}
	default:
		t.Fatal("POP3 greeting did not set a connection deadline")
	}
}

func TestReferenceIMAPAllowsIdleConnections(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deadlines := make(chan time.Time, 1)
	go newIMAPHandler()(&SessionConnection{
		Conn:       observedDeadlineConn{Conn: server, deadline: deadlines},
		ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}},
	})
	reader := bufio.NewReader(client)
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "* OK ") {
		t.Fatalf("greeting = %q (%v)", greeting, err)
	}
	if _, err := io.WriteString(client, "a NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || reply != "a OK NOOP completed\r\n" {
		t.Fatalf("NOOP reply = %q (%v)", reply, err)
	}
	select {
	case deadline := <-deadlines:
		if !deadline.IsZero() {
			t.Fatalf("IMAP set a connection deadline: %v", deadline)
		}
	default:
	}
}

func TestReferenceIMAPMailboxHierarchy(t *testing.T) {
	listener := &imapListener{accounts: make(map[string]*imapAccount)}
	account := listener.account("fixture")
	var selected imapSelectedMailbox
	for _, tc := range []struct {
		command, argument, want string
	}{
		{"LIST", `"" ""`, "* LIST (\\Noselect) \"/\" \"/\"\r\na OK LIST completed\r\n"},
		{"LSUB", `"" ""`, "a OK LSUB completed\r\n"},
		{"CREATE", "Archive/2025", "a OK CREATE completed\r\n"},
		{"CREATE", "Archive", "a OK CREATE completed\r\n"},
		{"SUBSCRIBE", "Archive", "a OK SUBSCRIBE completed\r\n"},
		{"LIST", `"Archive" "%"`, "* LIST () \"/\" \"Archive/2025\"\r\na OK LIST completed\r\n"},
		{"LIST", `"Archive/" "/%"`, "* LIST () \"/\" \"Archive\"\r\n* LIST () \"/\" INBOX\r\na OK LIST completed\r\n"},
		{"LSUB", `"Archive/" ""`, "* LSUB (\\Noselect) \"/\" \"/\"\r\na OK LSUB completed\r\n"},
		{"RENAME", "Archive Saved", "a OK RENAME completed\r\n"},
		{"LSUB", `"" "*"`, "a OK LSUB completed\r\n"},
		{"LIST", `"" "Archive/*"`, "* LIST () \"/\" \"Archive/2025\"\r\na OK LIST completed\r\n"},
	} {
		if got := account.mailboxReply("a", tc.command, tc.argument, &selected); got != tc.want {
			t.Errorf("%s %s got %q, want %q", tc.command, tc.argument, got, tc.want)
		}
	}
}

func TestReferenceIMAPSelectionTransitions(t *testing.T) {
	listener := &imapListener{accounts: make(map[string]*imapAccount)}
	account := listener.account("fixture")
	var selected imapSelectedMailbox
	command := func(name, argument string) string {
		return account.mailboxReply("a", name, argument, &selected)
	}
	for _, tc := range []struct {
		command, argument, want string
		selected                bool
	}{
		{"SELECT", "Missing", "a NO No such mailbox\r\n", false},
		{"EXAMINE", "Missing", "a NO No such mailbox\r\n", false},
		{"SELECT", `""`, "a NO No such mailbox\r\n", false},
		{"SELECT", "", "a BAD No enough arguments\r\n", true},
	} {
		command("SELECT", "INBOX")
		if got := command(tc.command, tc.argument); got != tc.want || (selected.box != nil) != tc.selected {
			t.Errorf("%s %s got %q with selected=%v, want %q with selected=%v", tc.command, tc.argument, got, selected.box != nil, tc.want, tc.selected)
		}
	}
	command("SUBSCRIBE", "INBOX")
	command("RENAME", "INBOX Migrated")
	if selected.box != account.boxes["INBOX"] || len(selected.box.messages) != 0 || !selected.box.subscribed || account.boxes["Migrated"].subscribed {
		t.Fatal("renamed INBOX did not leave the selected INBOX empty and subscribed")
	}
	command("SELECT", "Migrated")
	command("DELETE", "Migrated")
	if selected.box == nil || len(selected.box.messages) != 1 || selected.box.messages[0].uid != 6 {
		t.Fatal("deleted mailbox did not preserve the existing selection's message")
	}
}

func TestReferenceMailboxSessions(t *testing.T) {
	internalDate := regexp.MustCompile(`INTERNALDATE "\d\d-[A-Za-z]{3}-\d{4} \d\d:\d\d:\d\d [+-]\d{4}"`)
	var cases []struct {
		Name, Handler, Profile string
		Steps                  []struct{ Command, Response string }
	}
	if err := json.Unmarshal(referenceMailbox, &cases); err != nil {
		t.Fatal(err)
	}
	listeners := make(map[string]func(*SessionConnection) error)
	for _, c := range cases {
		if c.Profile != "default" && c.Profile != "plain" && c.Profile != "state" {
			continue // TLS cases run through the full ProtoSim listener in the differential runner.
		}
		t.Run(c.Name, func(t *testing.T) {
			params := map[string]any{"accounts": []any{"fixture:lab-only"}}
			if c.Profile == "plain" || c.Profile == "state" {
				params["allow_insecure_auth"] = true
			}
			if c.Profile == "state" {
				params["accounts"] = []any{"fixture:lab-only", "other:lab-only"}
			}
			var exchanges []referenceExchange
			literalDates := make(map[string]bool)
			const clockPlaceholder = `INTERNALDATE "01-Jan-2000 00:00:00 +0000"`
			for _, step := range c.Steps {
				exchanges = append(exchanges, referenceExchange{step.Command, step.Response})
				for _, date := range internalDate.FindAllString(step.Response, -1) {
					if date != clockPlaceholder {
						literalDates[date] = true
					}
				}
			}
			normalize := func(reply string) string {
				reply = internalDate.ReplaceAllStringFunc(reply, func(date string) string {
					if literalDates[date] {
						return date
					}
					return clockPlaceholder
				})
				if strings.Contains(reply, " OK [READ-") || strings.HasPrefix(reply, "* LIST ") || strings.HasPrefix(reply, "* LSUB ") {
					lines := strings.SplitAfter(strings.TrimSuffix(reply, "\r\n"), "\r\n")
					for i, line := range lines[:len(lines)-1] {
						flags, ok := strings.CutPrefix(line, "* FLAGS (")
						if ok {
							items := strings.Fields(strings.TrimSuffix(flags, ")\r\n"))
							slices.Sort(items)
							lines[i] = "* FLAGS (" + strings.Join(items, " ") + ")\r\n"
						}
					}
					slices.Sort(lines[:len(lines)-1])
					return strings.Join(lines, "") + "\r\n"
				}
				return reply
			}
			if c.Handler == "imap" {
				if listeners[c.Profile] == nil {
					listeners[c.Profile] = newIMAPHandler()
				}
				requireReferenceTCPHandler(t, listeners[c.Profile], params, exchanges, normalize)
			} else {
				requireReferenceTCP(t, c.Handler, params, exchanges, normalize)
			}
		})
	}
}
