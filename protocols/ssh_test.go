package protocols

import (
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func listenReferenceSSH(t *testing.T, endpoint string) (string, <-chan time.Time) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	deadlines := make(chan time.Time, 4)
	serve := referenceTCPHandler(t, "ssh")
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serve(&SessionConnection{Conn: observedDeadlineConn{Conn: conn, deadline: deadlines}, ConfigInfo: &ConfigInfo{ServerInfo: endpoint, BindInfo: &BindInfo{
				Params: map[string]any{
					"accounts": []any{"fixture:lab-only:/home/fixture:1000"},
					"prompt":   "LAB> ",
				},
			}}})
		}
	}()
	return listener.Addr().String(), deadlines
}

func dialReferenceSSH(address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	client, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(client, channels, requests), nil
}

func startReferenceSSHServer(t *testing.T) (func(string) (*ssh.Client, error), <-chan time.Time) {
	t.Helper()
	address, deadlines := listenReferenceSSH(t, "")
	dial := func(password string) (*ssh.Client, error) {
		cfg := &ssh.ClientConfig{
			User: "fixture", Auth: []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Loopback test server.
		}
		return dialReferenceSSH(address, cfg)
	}
	return dial, deadlines
}

func TestReferenceSSHHostKeysAreListenerLocalRSA(t *testing.T) {
	t.Chdir(t.TempDir())
	const firstEndpoint = "127.0.0.1:22224"
	first, _ := listenReferenceSSH(t, firstEndpoint)
	second, _ := listenReferenceSSH(t, "127.0.0.1:22225")
	keyFor := func(address, algorithm string) string {
		t.Helper()
		var publicKey ssh.PublicKey
		client, err := dialReferenceSSH(address, &ssh.ClientConfig{
			User:              "fixture",
			Auth:              []ssh.AuthMethod{ssh.Password("lab-only")},
			HostKeyAlgorithms: []string{algorithm},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				publicKey = key
				return nil
			},
		})
		if err != nil {
			t.Fatalf("handshake with %s: %v", algorithm, err)
		}
		defer client.Close()
		key, ok := publicKey.(ssh.CryptoPublicKey)
		if !ok {
			t.Fatalf("unexpected SSH public key: %T", publicKey)
		}
		rsaKey, ok := key.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() != 2048 {
			t.Fatalf("unexpected SSH host public key: %T", key.CryptoPublicKey())
		}
		return ssh.FingerprintSHA256(publicKey)
	}

	firstKey := keyFor(first, ssh.KeyAlgoRSASHA256)
	if keyFor(first, ssh.KeyAlgoRSASHA512) != firstKey || keyFor(first, ssh.KeyAlgoRSA) != firstKey {
		t.Fatal("host key changed when the signature algorithm changed")
	}
	if keyFor(second, ssh.KeyAlgoRSASHA256) == firstKey {
		t.Fatal("two SSH listeners share the same host key")
	}
	reopened, _ := listenReferenceSSH(t, firstEndpoint)
	if keyFor(reopened, ssh.KeyAlgoRSASHA256) != firstKey {
		t.Fatal("reopened SSH endpoint returned a new host key")
	}
	info, err := os.Stat(firstEndpoint + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("host key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestSSHConcurrentHostKeyCreationUsesOneKey(t *testing.T) {
	t.Chdir(t.TempDir())
	const endpoint = "127.0.0.1:22224"
	type result struct {
		signer ssh.Signer
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			signer, err := loadOrCreateSSHHostKey(endpoint)
			results <- result{signer, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent host-key reads = %v, %v", first.err, second.err)
	}
	persisted, err := loadOrCreateSSHHostKey(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	key := ssh.FingerprintSHA256(persisted.PublicKey())
	if ssh.FingerprintSHA256(first.signer.PublicKey()) != key || ssh.FingerprintSHA256(second.signer.PublicKey()) != key {
		t.Fatal("concurrent SSH listeners used different keys for the same endpoint")
	}
}

func TestReferenceSSHInteractiveSession(t *testing.T) {
	dial, _ := startReferenceSSHServer(t)
	if client, err := dial("wrong"); err == nil {
		client.Close()
		t.Fatal("rejected password accepted")
	}
	client, err := dial("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if forwarded, err := client.Dial("tcp", "127.0.0.1:1"); err == nil {
		forwarded.Close()
		t.Fatal("simulated SSH listener accepted forwarding")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	read := func(want string) {
		t.Helper()
		data := make([]byte, len(want))
		if _, err := io.ReadFull(stdout, data); err != nil || string(data) != want {
			t.Fatalf("reply = %q (%v), want %q", data, err, want)
		}
	}
	read("LAB> ")
	for _, pair := range [][2]string{
		{"whoami", "fixture"}, {"pwd", "/home/fixture"},
		{"id", "uid=1000(fixture) gid=0(root) groups=0(root)"}, {"ls", ". .."},
		{"foobar", "command not found: foobar"},
	} {
		if _, err := io.WriteString(stdin, pair[0]+"\n"); err != nil {
			t.Fatal(err)
		}
		read(pair[0] + "\r\n" + pair[1] + "\r\nLAB> ")
	}
	if _, err := io.WriteString(stdin, "exit\n"); err != nil {
		t.Fatal(err)
	}
	read("exit\r\n")
	var missingStatus *ssh.ExitMissingError
	if err := session.Wait(); !errors.As(err, &missingStatus) {
		t.Fatalf("reference closes without an SSH exit status; got %v", err)
	}
}

func TestReferenceSSHDoesNotSetConnectionDeadline(t *testing.T) {
	dial, deadlines := startReferenceSSHServer(t)
	client, err := dial("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	select {
	case deadline := <-deadlines:
		if !deadline.IsZero() {
			t.Fatalf("SSH set a connection deadline: %v", deadline)
		}
	default:
	}
}

func TestReferenceSSHQueuesSecondChannelUntilShellCloses(t *testing.T) {
	dial, _ := startReferenceSSHServer(t)
	client, err := dial("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	stdin, err := first.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := first.Shell(); err != nil {
		t.Fatal(err)
	}
	opened := make(chan error, 1)
	go func() {
		second, err := client.NewSession()
		if err == nil {
			second.Close()
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		t.Fatalf("second channel completed while first shell was open: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second channel did not open after closing the first shell")
	}
}

func TestSSHExecRepliesAndStartsShell(t *testing.T) {
	dial, _ := startReferenceSSHServer(t)
	client, err := dial("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	replied := make(chan bool, 1)
	go func() {
		ok, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"whoami"}))
		replied <- (err == nil && ok)
	}()
	const prompt = "LAB> "
	output := make([]byte, len(prompt))
	if _, err := io.ReadFull(channel, output); err != nil || string(output) != prompt {
		t.Fatalf("exec output = %q (%v), want %q", output, err, prompt)
	}
	select {
	case ok := <-replied:
		if !ok {
			t.Fatal("exec request was not accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("exec request did not receive RFC 4254 reply")
	}
}
