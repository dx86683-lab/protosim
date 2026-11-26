package protocols

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	imapMailboxLimit = 64
	imapMessageLimit = 128
	imapLiteralLimit = 64 << 10
	imapFlagLimit    = 128
)

type imapListener struct {
	mu       sync.Mutex
	accounts map[string]*imapAccount
	date     time.Time
}

type imapAccount struct {
	mu    sync.Mutex
	boxes map[string]*imapMailbox
}

type imapMailbox struct {
	messages   []imapMessage
	subscribed bool
}

type imapMessage struct {
	uid     uint32
	flags   []string
	date    time.Time
	headers string
	text    string
	seed    bool
	mime    *imapMIMEPart
}

type imapSelectedMailbox struct {
	box  *imapMailbox
	mode imapSelection
}

func (l *imapListener) account(user string) *imapAccount {
	l.mu.Lock()
	defer l.mu.Unlock()
	account := l.accounts[user]
	if account == nil {
		inbox := &imapMailbox{messages: []imapMessage{{
			uid: 6, flags: []string{`\Seen`}, date: l.date, headers: imapHeaders, text: imapText, seed: true,
		}}}
		account = &imapAccount{boxes: map[string]*imapMailbox{"INBOX": inbox}}
		l.accounts[user] = account
	}
	return account
}

func (b *imapMailbox) nextUID() uint32 {
	if len(b.messages) == 0 {
		return 1
	}
	return b.messages[len(b.messages)-1].uid + 1
}

func (a *imapAccount) messageCount() int {
	n := 0
	for _, box := range a.boxes {
		n += len(box.messages)
	}
	return n
}

func imapMailboxName(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	return name
}

func imapMailboxWire(name string) string {
	if name == "INBOX" {
		return name
	}
	return strconv.Quote(encodeIMAPMailboxName(name))
}

func imapMailboxPattern(reference, pattern string) (*regexp.Regexp, error) {
	if absolute, ok := strings.CutPrefix(pattern, "/"); ok {
		reference, pattern = "", absolute
	}
	if reference != "" && !strings.HasSuffix(reference, "/") {
		reference += "/"
	}
	re := regexp.QuoteMeta(pattern)
	re = strings.NewReplacer(`\*`, ".*", "%", "[^/]*").Replace(re)
	return regexp.Compile("^" + regexp.QuoteMeta(reference) + "(?:" + re + ")$")
}

func (a *imapAccount) mailboxReply(tag, command, argument string, selected *imapSelectedMailbox) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	done := tag + " OK " + command + " completed\r\n"
	if command == "LIST" || command == "LSUB" || command == "STATUS" {
		return a.mailboxQueryReply(tag, command, argument, done)
	}
	first, rest, ok := cutIMAPArgument(argument)
	if !ok {
		return tag + " BAD No enough arguments\r\n"
	}
	name, valid := decodeIMAPMailboxName(first)
	if !valid {
		return tag + imapInvalidMailboxEncoding
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return tag + " BAD No enough arguments\r\n"
	}
	if command == "SELECT" || command == "EXAMINE" {
		*selected = imapSelectedMailbox{}
	} else if name == "" {
		return tag + " BAD No enough arguments\r\n"
	}
	box := a.boxes[name]
	if command == "CREATE" {
		switch {
		case box != nil:
			return tag + " NO Mailbox already exists\r\n"
		case len(a.boxes) >= imapMailboxLimit:
			return tag + " NO Mailbox limit reached\r\n"
		}
		a.boxes[name] = &imapMailbox{}
		return done
	}
	if box == nil {
		return tag + " NO No such mailbox\r\n"
	}
	switch command {
	case "DELETE":
		if name == "INBOX" {
			return tag + " NO Cannot delete INBOX\r\n"
		}
		delete(a.boxes, name)
	case "RENAME":
		target, _, ok := cutIMAPArgument(rest)
		if !ok || target == "" {
			return tag + " BAD No enough arguments\r\n"
		}
		target, valid := decodeIMAPMailboxName(target)
		if !valid {
			return tag + imapInvalidMailboxEncoding
		}
		if strings.ContainsAny(target, "\r\n\x00") {
			return tag + " BAD No enough arguments\r\n"
		}
		if a.boxes[target] != nil {
			return tag + " NO Mailbox already exists\r\n"
		}
		if name == "INBOX" && len(a.boxes) >= imapMailboxLimit {
			return tag + " NO Mailbox limit reached\r\n"
		}
		a.boxes[target] = &imapMailbox{messages: box.messages}
		box.messages = nil
		if name != "INBOX" {
			delete(a.boxes, name)
		}
	case "SUBSCRIBE", "UNSUBSCRIBE":
		box.subscribed = command == "SUBSCRIBE"
	case "SELECT", "EXAMINE":
		selected.box, selected.mode = box, imapReadWrite
		mode := "[READ-WRITE]"
		if command == "EXAMINE" {
			selected.mode = imapReadOnly
			mode = "[READ-ONLY]"
		}
		return box.selectionReply() + tag + " OK " + mode + " " + command + " completed\r\n"
	}
	return done
}

func (a *imapAccount) mailboxQueryReply(tag, command, argument, done string) string {
	tokens, ok := tokenizeIMAPArguments(argument)
	first, remaining := takeIMAPArgument(tokens)
	second, _ := takeIMAPArgument(remaining)
	if !ok || len(first) == 0 || len(second) == 0 {
		return tag + " BAD No enough arguments\r\n"
	}
	if !first[0].isString() {
		return tag + " BAD expected a string\r\n"
	}
	if command == "STATUS" {
		return a.statusReply(tag, done, first[0].text, second)
	}
	if !second[0].isString() {
		return tag + " BAD expected a string\r\n"
	}
	reference, validReference := decodeIMAPMailboxName(first[0].text)
	pattern, validPattern := decodeIMAPMailboxName(second[0].text)
	if !validReference || !validPattern {
		return tag + imapInvalidMailboxEncoding
	}
	match, err := imapMailboxPattern(reference, pattern)
	if err != nil {
		return tag + " BAD Invalid mailbox pattern\r\n"
	}
	var names []string
	for name, box := range a.boxes {
		if command == "LSUB" && !box.subscribed {
			continue
		}
		if pattern == "" {
			return "* " + command + " (\\Noselect) \"/\" \"/\"\r\n" + done
		}
		if match.MatchString(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "* %s () \"/\" %s\r\n", command, imapMailboxWire(name))
	}
	return out.String() + done
}

func (a *imapAccount) statusReply(tag, done, mailbox string, list []imapArgumentToken) string {
	if list[0].delimiter != '(' {
		return tag + " BAD STATUS command parameter is not a list\r\n"
	}
	items := list[1 : len(list)-1]
	for _, item := range items {
		if !item.isString() || strings.ContainsAny(item.text, "()\r\n\x00") {
			return tag + " BAD Got a non-string field in a STATUS command parameter\r\n"
		}
	}
	name, valid := decodeIMAPMailboxName(mailbox)
	if !valid {
		return tag + imapInvalidMailboxEncoding
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return tag + " BAD No enough arguments\r\n"
	}
	box := a.boxes[name]
	if box == nil {
		return tag + " NO No such mailbox\r\n"
	}
	seen := make(map[string]struct{}, len(items))
	fields := make([]string, 0, len(items))
	for _, item := range items {
		key := strings.ToUpper(item.text)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		value := "NIL"
		switch key {
		case "MESSAGES":
			value = strconv.Itoa(len(box.messages))
		case "UIDVALIDITY":
			value = "1"
		case "RECENT", "UNSEEN":
			value = "0"
		case "UIDNEXT":
			value = strconv.FormatUint(uint64(box.nextUID()), 10)
		}
		fields = append(fields, key+" "+value)
	}
	return "* STATUS " + imapMailboxWire(name) + " (" + strings.Join(fields, " ") + ")\r\n" + done
}

func (b *imapMailbox) selectionReply() string {
	var flags []string
	unseen := 0
	for i, message := range b.messages {
		if unseen == 0 && !message.hasFlag(`\Seen`) {
			unseen = i + 1
		}
		for _, flag := range message.flags {
			if !slices.Contains(flags, flag) {
				flags = append(flags, flag)
			}
		}
	}
	var out strings.Builder
	if len(flags) != 0 {
		fmt.Fprintf(&out, "* FLAGS (%s)\r\n", strings.Join(flags, " "))
	}
	out.WriteString("* OK [PERMANENTFLAGS (\\*)] Flags permitted.\r\n")
	fmt.Fprintf(&out, "* %d EXISTS\r\n* 0 RECENT\r\n", len(b.messages))
	if unseen != 0 {
		fmt.Fprintf(&out, "* OK [UNSEEN %d] Message %d is first unseen\r\n", unseen, unseen)
	}
	fmt.Fprintf(&out, "* OK [UIDNEXT %d] Predicted next UID\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n", b.nextUID())
	return out.String()
}

func (m *imapMessage) hasFlag(flag string) bool {
	return slices.ContainsFunc(m.flags, func(item string) bool { return strings.EqualFold(item, flag) })
}

func imapFlags(input string) []string {
	var flags []string
	for _, flag := range strings.Fields(strings.Trim(input, "() ")) {
		flag = strings.ToLower(flag)
		switch flag {
		case `\seen`, `\answered`, `\flagged`, `\deleted`, `\draft`, `\recent`:
			flag = "\\" + strings.ToUpper(flag[1:2]) + flag[2:]
		}
		flags = append(flags, flag)
	}
	return flags
}

func (a *imapAccount) appendMessage(session *SessionConnection, reader *bufio.Reader, tag, argument string) (string, error) {
	name, rest, ok := cutIMAPArgument(argument)
	start := strings.LastIndex(rest, "{")
	if !ok || start < 0 || !strings.HasSuffix(rest, "}") {
		return tag + " BAD Invalid arguments\r\n", nil
	}
	length := rest[start+1 : len(rest)-1]
	length, nonsync := strings.CutSuffix(length, "+")
	size, err := strconv.ParseUint(length, 10, 32)
	if err != nil || size > imapLiteralLimit {
		if nonsync {
			return "", fmt.Errorf("invalid IMAP literal length")
		}
		return tag + " NO Literal too large\r\n", nil
	}
	options := strings.TrimSpace(rest[:start])
	var flags []string
	if flagsInput, ok := strings.CutPrefix(options, "("); ok {
		list, remainder, valid := strings.Cut(flagsInput, ")")
		if !valid {
			return "", fmt.Errorf("invalid IMAP flags")
		}
		flags, options = imapFlags(list), strings.TrimSpace(remainder)
	}
	date := time.Now()
	if options != "" {
		value, tail, valid := cutIMAPArgument(options)
		parsed, dateErr := time.Parse("_2-Jan-2006 15:04:05 -0700", value)
		if !valid || tail != "" || dateErr != nil {
			return "", fmt.Errorf("invalid IMAP append date")
		}
		date = parsed
	}
	if !nonsync {
		if err := session.SendString("+ send literal\r\n"); err != nil {
			return "", err
		}
	}
	wire := make([]byte, int(size)+2)
	if _, err := io.ReadFull(reader, wire); err != nil {
		return "", err
	}
	if string(wire[size:]) != "\r\n" {
		return "", fmt.Errorf("invalid IMAP literal terminator")
	}
	name, valid := decodeIMAPMailboxName(name)
	if !valid {
		return tag + imapInvalidMailboxEncoding, nil
	}
	content := string(wire[:size])
	headers, text := imapSplitMessage(content)
	a.mu.Lock()
	defer a.mu.Unlock()
	box := a.boxes[name]
	if box == nil {
		return tag + " NO No such mailbox\r\n", nil
	}
	if a.messageCount() >= imapMessageLimit || len(flags) > imapFlagLimit {
		return tag + " NO Mailbox message limit reached\r\n", nil
	}
	box.messages = append(box.messages, imapMessage{uid: box.nextUID(), flags: flags, date: date, headers: headers, text: text})
	return tag + " OK APPEND completed\r\n", nil
}

func (a *imapAccount) selectedReply(tag, command, argument string, selected *imapSelectedMailbox) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	uid := command == "UID"
	prefix := command
	if uid {
		command, argument, _ = strings.Cut(strings.TrimSpace(argument), " ")
		command = strings.ToUpper(command)
		switch command {
		case "SEARCH", "FETCH", "STORE", "COPY", "MOVE":
		case "CHECK", "CLOSE", "UNSELECT", "EXPUNGE":
			return tag + " NO Command unsupported with UID\r\n"
		default:
			return tag + " NO Unknown command\r\n"
		}
		prefix += " " + command
	}
	done := tag + " OK " + prefix + " completed\r\n"
	readOnly := selected.mode == imapReadOnly
	const readOnlyReply = " NO Mailbox opened in read-only mode\r\n"
	box := selected.box
	switch command {
	case "CHECK":
		if readOnly {
			return tag + readOnlyReply
		}
	case "CLOSE":
		if !readOnly {
			box.expunge()
		}
		*selected = imapSelectedMailbox{}
	case "UNSELECT":
		*selected = imapSelectedMailbox{}
	case "SEARCH":
		return imapSearchReply(tag, done, argument, uid, box.messages)
	case "FETCH":
		return imapFetchReply(tag, done, argument, uid, box.messages)
	case "STORE":
		if readOnly {
			return tag + readOnlyReply
		}
		return box.storeFlags(tag, done, argument, uid)
	case "COPY":
		return a.copyMessages(tag, done, argument, uid, box)
	case "EXPUNGE":
		if readOnly {
			return tag + readOnlyReply
		}
		return box.expunge() + done
	case "MOVE":
		return tag + " NO MOVE extension not supported\r\n"
	default:
		return tag + " BAD Unknown command\r\n"
	}
	return done
}

func imapMatchingMessages(messages []imapMessage, sequence string, uid bool) ([]int, error) {
	if _, err := imapSequenceMatch(sequence, 0); err != nil {
		return nil, err
	}
	var indices []int
	for i, msg := range messages {
		id := uint32(i + 1)
		if uid {
			id = msg.uid
		}
		if ok, _ := imapSequenceMatch(sequence, id); ok {
			indices = append(indices, i)
		}
	}
	return indices, nil
}

func (a *imapAccount) copyMessages(tag, done, argument string, uid bool, from *imapMailbox) string {
	sequence, rest, ok := cutIMAPArgument(argument)
	target, _, valid := cutIMAPArgument(rest)
	if !ok || !valid {
		return tag + " BAD No enough arguments\r\n"
	}
	target, valid = decodeIMAPMailboxName(target)
	if !valid {
		return tag + imapInvalidMailboxEncoding
	}
	to := a.boxes[target]
	if to == nil {
		return tag + " NO No such mailbox\r\n"
	}
	indices, err := imapMatchingMessages(from.messages, sequence, uid)
	if err != nil {
		return tag + " BAD " + err.Error() + "\r\n"
	}
	if len(indices)+a.messageCount() > imapMessageLimit {
		return tag + " NO Mailbox message limit reached\r\n"
	}
	for _, index := range indices {
		// The reference copies message metadata and shares the backing flag slice.
		message := from.messages[index]
		message.uid = to.nextUID()
		to.messages = append(to.messages, message)
	}
	return done
}

func (b *imapMailbox) storeFlags(tag, done, argument string, uid bool) string {
	sequence, rest, ok := cutIMAPArgument(argument)
	op, list, valid := cutIMAPArgument(rest)
	if !ok || !valid || list == "" {
		return tag + " BAD No enough arguments\r\n"
	}
	op, silent := strings.CutSuffix(strings.ToUpper(op), ".SILENT")
	if op != "FLAGS" && op != "+FLAGS" && op != "-FLAGS" {
		return tag + " BAD Invalid STORE item\r\n"
	}
	indices, err := imapMatchingMessages(b.messages, sequence, uid)
	if err != nil {
		return tag + " BAD " + err.Error() + "\r\n"
	}
	flags := imapFlags(list)
	if len(flags) > imapFlagLimit {
		return tag + " NO Flag limit reached\r\n"
	}
	if op == "+FLAGS" {
		for _, index := range indices {
			if len(b.messages[index].flags)+len(flags) > imapFlagLimit {
				return tag + " NO Flag limit reached\r\n"
			}
		}
	}
	var out strings.Builder
	for _, index := range indices {
		m := &b.messages[index]
		if op == "FLAGS" {
			m.flags = m.flags[:0]
		}
		if op == "-FLAGS" {
			kept := m.flags[:0]
			for _, flag := range m.flags {
				if !slices.Contains(flags, flag) {
					kept = append(kept, flag)
				}
			}
			m.flags = kept
		} else {
			for _, flag := range flags {
				if !m.hasFlag(flag) {
					m.flags = append(m.flags, flag)
				}
			}
		}
		if !silent {
			fmt.Fprintf(&out, "* %d FETCH (FLAGS (%s)", index+1, strings.Join(m.flags, " "))
			if uid {
				fmt.Fprintf(&out, " UID %d", m.uid)
			}
			out.WriteString(")\r\n")
		}
	}
	return out.String() + done
}

func (b *imapMailbox) expunge() string {
	var out strings.Builder
	kept := b.messages[:0]
	for _, msg := range b.messages {
		if msg.hasFlag(`\Deleted`) {
			fmt.Fprintf(&out, "* %d EXPUNGE\r\n", len(kept)+1)
		} else {
			kept = append(kept, msg)
		}
	}
	clear(b.messages[len(kept):])
	b.messages = kept
	return out.String()
}
