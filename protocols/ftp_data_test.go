package protocols

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFTPActiveTransferRestrictions(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	control, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	session := &SessionConnection{Conn: control, DialTCPPeer: func(_ context.Context, port uint16) (net.Conn, error) {
		t.Fatalf("unexpected data connection to port %d", port)
		return nil, nil
	}}
	ftp := ftpControl{loggedIn: true}
	for _, test := range []struct{ command, argument string }{
		{"PORT", "127,0,0,2,195,80"},
		{"PORT", "127,0,0,1,0,21"},
		{"EPRT", "|1|127.0.0.2|50000|"},
		{"EPRT", "|1|127.0.0.1|21|"},
	} {
		reply, err := ftp.command(session, test.command, test.argument)
		if err != nil || reply != "425 Data connection failed" {
			t.Errorf("%s %s returned %q, %v", test.command, test.argument, reply, err)
		}
	}
	if reply, err := ftp.command(session, "LPRT", "4,4,127,0,0,1,2,195,80"); err != nil || reply != "" {
		t.Errorf("LPRT without a selected endpoint returned %q, %v", reply, err)
	}
	previous, peer := net.Pipe()
	defer previous.Close()
	defer peer.Close()
	ftp.active = previous
	if reply, err := ftp.command(session, "LPRT", "4,4,127,0,0,1,2,0,21"); err != nil || reply != ftpDataConnectionFailed {
		t.Errorf("LPRT to a privileged port returned %q, %v", reply, err)
	}
}

func TestFTPRenameWithoutSourceReleasesReplacedFile(t *testing.T) {
	for _, target := range []string{"/text.txt", "/text.txt/child"} {
		files := newFTPVolume()
		if err := files.renameEntry("", target); err != nil {
			t.Fatalf("RNTO %s: %v", target, err)
		}
		info, err := files.Stat(target)
		if err != nil || !info.IsDir() || files.used != 0 {
			t.Fatalf("RNTO %s: entry=%v, err=%v, volume bytes=%d", target, info, err, files.used)
		}
	}
}

func TestReferenceFTPPassiveTransfer(t *testing.T) {
	listen := func() (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") }
	listener, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler := newFTPHandler()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			handler(&SessionConnection{Conn: conn, ListenEphemeralTCP: listen, ConfigInfo: &ConfigInfo{
				BindInfo: &BindInfo{Params: map[string]any{"accounts": []any{"fixture:lab-only"}}},
			}})
		}
	}()
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	read := func(want string) string {
		t.Helper()
		wire, err := reader.ReadString('\n')
		wire = strings.TrimSuffix(wire, "\r\n")
		if err != nil || want != "" && wire != want {
			t.Fatalf("got %q (%v), want %q", wire, err, want)
		}
		return wire
	}
	send := func(command, want string) string {
		t.Helper()
		if _, err := fmt.Fprint(conn, command+"\r\n"); err != nil {
			t.Fatal(err)
		}
		return read(want)
	}
	openData := func() net.Conn {
		t.Helper()
		reply := send("EPSV", "")
		port, ok := strings.CutPrefix(reply, "229 Entering Extended Passive Mode (|||")
		if !ok {
			t.Fatalf("EPSV reply: %q", reply)
		}
		port = strings.TrimSuffix(port, "|)")
		if _, err := strconv.Atoi(port); err != nil {
			t.Fatal(err)
		}
		data, err := net.DialTimeout("tcp4", "127.0.0.1:"+port, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		data.SetDeadline(time.Now().Add(time.Second))
		t.Cleanup(func() { data.Close() })
		return data
	}
	read("220 Welcome to the FTP Server")
	send("PASV", "530 not logged in")
	send("USER fixture", "331 User name ok, password required")
	send("PASS lab-only", "230 Password ok, continue")
	send("SIZE text.txt", "213 4")
	data := openData()
	send("NLST", "150 Opening ASCII mode data connection for file list")
	if body, err := io.ReadAll(data); err != nil || string(body) != "text.txt\r\n" {
		t.Fatalf("NLST = %q, %v", body, err)
	}
	read("226 Closing data connection, sent 10 bytes")
	data = openData()
	send("NLST -a text.txt", "550 -a text.txt is not a directory")
	send("MLSD absent-listing.txt", "550 file does not exist")
	send("LIST absent-listing.txt", "150 Opening ASCII mode data connection for file list")
	if body, err := io.ReadAll(data); err != nil || len(body) != 0 {
		t.Fatalf("LIST missing file = %q, %v", body, err)
	}
	read("226 Closing data connection, sent 0 bytes")
	data = openData()
	send("STOR fixture.txt", "150 Data transfer starting")
	if _, err := io.WriteString(data, "lab fixture"); err != nil {
		t.Fatal(err)
	}
	data.Close()
	read("226 OK, received 11 bytes")
	send("SIZE fixture.txt", "213 11")
	send("REST +0003", "350 Start transfer from 3")
	send("REST invalid", "551 File not available")
	data = openData()
	send("RETR fixture.txt", "150 Data transfer starting 11 bytes")
	if body, err := io.ReadAll(data); err != nil || string(body) != "lab fixture" {
		t.Fatalf("RETR = %q, %v", body, err)
	}
	read("226 Closing data connection, sent 11 bytes")
	data = openData()
	send("REST 4", "350 Start transfer from 4")
	send("RETR fixture.txt", "150 Data transfer starting 7 bytes")
	if body, err := io.ReadAll(data); err != nil || string(body) != "fixture" {
		t.Fatalf("resumed RETR = %q, %v", body, err)
	}
	read("226 Closing data connection, sent 7 bytes")
	data = openData()
	send("REST 12", "350 Start transfer from 12")
	send("RETR fixture.txt", "150 Data transfer starting -1 bytes")
	read("551 Error reading file")
	data.Close()
	data = openData()
	send("REST 3", "350 Start transfer from 3")
	send("STOR fixture.txt", "150 Data transfer starting")
	if _, err := io.WriteString(data, "new"); err != nil {
		t.Fatal(err)
	}
	data.Close()
	read("226 OK, received 3 bytes")
	data = openData()
	send("RETR fixture.txt", "150 Data transfer starting 17 bytes")
	if body, err := io.ReadAll(data); err != nil || string(body) != "lab fixture\x00\x00\x00new" {
		t.Fatalf("resumed STOR content = %q, %v", body, err)
	}
	read("226 Closing data connection, sent 17 bytes")
	send("RNFR fixture.txt", "350 Requested file action pending further information.")
	send("NOOP", "200 OK")
	send("RNTO renamed.txt", "250 File renamed")
	send("SIZE fixture.txt", "450 path fixture.txt not found")
	send("SIZE renamed.txt", "213 17")
	send("RNTO unexpected.txt", "250 File renamed")
	send("SIZE unexpected.txt", "213 42")
	send("REST -3", "350 Start transfer from -3")
	data = openData()
	send("APPE renamed.txt", "150 Data transfer starting")
	if _, err := io.WriteString(data, "new"); err != nil {
		t.Fatal(err)
	}
	data.Close()
	read("226 OK, received 3 bytes")
	send("SIZE renamed.txt", "213 3")
	send("DELE renamed.txt", "250 File deleted")
	send("MKD fixture-dir", "257 Directory created")
	data = openData()
	send("STOR fixture-dir/file.txt", "150 Data transfer starting")
	if _, err := io.WriteString(data, "lab"); err != nil {
		t.Fatal(err)
	}
	data.Close()
	read("226 OK, received 3 bytes")
	send("RNFR fixture-dir", "350 Requested file action pending further information.")
	send("RNTO moved-dir", "250 File renamed")
	send("SIZE moved-dir/file.txt", "213 3")
	send("SIZE fixture-dir/file.txt", "450 path fixture-dir/file.txt not found")
	send("RMD moved-dir", "250 Directory deleted")
	send("QUIT", "221 Goodbye")
}
