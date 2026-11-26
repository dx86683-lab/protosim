package protocols

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/dx86683-lab/protosim/fakeshell"
)

const sshServerVersion = "SSH-2.0-OpenSSH_7.4"
const sshPrompt = "$ "

var sshDefaultAccounts = []string{"root:123456:/root:0"}

func init() {
	AddProtocol(NewProtocolInfo("ssh", newSSHHandler, 22),
		ProtocolParams{Name: "accounts", DefaultValue: sshDefaultAccounts},
		ProtocolParams{Name: "server_version", DefaultValue: sshServerVersion},
		ProtocolParams{Name: "prompt", DefaultValue: sshPrompt})
}

type sshListener struct {
	hostKeyOnce sync.Once
	hostKey     ssh.Signer
	hostKeyErr  error
}

func newSSHHandler() func(*SessionConnection) error {
	return (&sshListener{}).serve
}

func (listener *sshListener) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	listener.hostKeyOnce.Do(func() {
		listener.hostKey, listener.hostKeyErr = loadOrCreateSSHHostKey(session.ServerInfo)
	})
	if listener.hostKeyErr != nil {
		return listener.hostKeyErr
	}
	version := session.GetStringParams("server_version", sshServerVersion)
	if !strings.HasPrefix(version, "SSH-2.0-") {
		version = "SSH-2.0-" + version
	}
	if strings.ContainsAny(version, "\r\n") {
		return errors.New("invalid SSH server version")
	}
	prompt := session.GetStringParams("prompt", sshPrompt)
	if strings.ContainsAny(prompt, "\r\n\x00") {
		return errors.New("invalid SSH shell prompt")
	}
	accounts := session.GetStringsParams("accounts", nil)
	var user fakeshell.FakeUserInfo
	config := &ssh.ServerConfig{
		ServerVersion: version,
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if len(accounts) == 0 {
				user = fakeshell.GetFakeRootUser()
				return nil, nil
			}
			for _, configured := range accounts {
				account := strings.Split(configured, ":")
				if len(account) != 4 || account[0] != metadata.User() ||
					subtle.ConstantTimeCompare([]byte(account[1]), password) != 1 {
					continue
				}
				user = fakeshell.FakeUserInfo{Username: account[0], Home: account[2], UID: account[3]}
				return nil, nil
			}
			return nil, errors.New("authentication rejected")
		},
	}
	config.AddHostKey(listener.hostKey)
	conn, channels, requests, err := ssh.NewServerConn(session.Conn, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "only simulated shell sessions are available")
			continue
		}
		serveSSHChannel(incoming, user, prompt)
	}
	return nil
}

func loadOrCreateSSHHostKey(endpoint string) (ssh.Signer, error) {
	var path string
	if endpoint != "" {
		if !filepath.IsLocal(endpoint) || filepath.Base(endpoint) != endpoint {
			return nil, errors.New("invalid SSH host key endpoint")
		}
		path = endpoint + ".key"
		data, err := os.ReadFile(path)
		if err == nil {
			return ssh.ParsePrivateKey(data)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := storeSSHHostKey(path, key); errors.Is(err, os.ErrExist) {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			return ssh.ParsePrivateKey(data)
		} else if err != nil {
			return nil, err
		}
	}
	return ssh.NewSignerFromKey(key)
}

func storeSSHHostKey(path string, key *rsa.PrivateKey) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ssh-host-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Publish atomically and preserve a key created by another process.
	return os.Link(file.Name(), path)
}

func serveSSHChannel(incoming ssh.NewChannel, user fakeshell.FakeUserInfo, prompt string) {
	channel, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	for request := range requests {
		switch request.Type {
		case "pty-req":
			_ = request.Reply(true, nil)
		case "env", "window-change":
			if request.WantReply {
				_ = request.Reply(true, nil)
			}
		case "shell", "exec":
			if request.WantReply {
				if err := request.Reply(true, nil); err != nil {
					return
				}
			}
			go ssh.DiscardRequests(requests)
			// Exec starts the same simulated shell. Its payload is never
			// interpreted as a host command.
			runSSHFakeShell(channel, user, prompt)
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func runSSHFakeShell(channel ssh.Channel, user fakeshell.FakeUserInfo, prompt string) {
	ioPair := struct {
		io.Reader
		io.Writer
	}{Reader: io.LimitReader(channel, 64<<10), Writer: channel}
	shell := fakeshell.NewShell(ioPair, user, false)
	shell.SetPrompt(prompt)
	for {
		args, err := shell.ReadCmdLine()
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		if args[0] == "exit" {
			return
		}
		output := shell.DoCmd(args[0], args[1:])
		if output != "" {
			if _, err := io.WriteString(channel, output+"\r\n"); err != nil {
				return
			}
		}
	}
}
