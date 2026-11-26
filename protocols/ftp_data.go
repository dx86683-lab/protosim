package protocols

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"

	"github.com/dx86683-lab/protosim/fakefs"
)

const ftpTransferLimit = 1 << 20
const ftpVolumeLimit = 8 << 20
const ftpTransferTimeout = 3 * time.Second

var errFTPTransfer = errors.New("error during transfer")

type ftpVolume struct {
	*fakefs.Fs
	mu   sync.Mutex
	used int64
}

func newFTPVolume() *ftpVolume {
	files := fakefs.NewMemMapFs()
	if err := afero.WriteFile(files, "/text.txt", []byte("test"), 0644); err != nil {
		panic(err) // The new, empty in-memory filesystem must accept its seed.
	}
	return &ftpVolume{Fs: files, used: 4}
}

func (v *ftpVolume) storeFile(name string, data []byte, offset int64, connected bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	var oldSize int64
	info, err := v.Stat(name)
	if err == nil {
		if info.IsDir() {
			if !connected {
				return fmt.Errorf("%w: A dir has the same name", errFTPTransfer)
			}
			return errors.New("cannot store over a simulated directory")
		}
		oldSize = info.Size()
	} else if errors.Is(err, fs.ErrNotExist) {
		if !connected && offset < 0 {
			return fmt.Errorf("%w: open %s: file does not exist", errFTPTransfer, name)
		}
		offset = 0
		if !connected {
			// Afero can turn an existing parent file into a directory when
			// creating a child. Keep the current file and report the conflict.
			for parent := path.Dir(name); parent != "/" && parent != "."; parent = path.Dir(parent) {
				parentInfo, err := v.Stat(parent)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				if !parentInfo.IsDir() {
					return fmt.Errorf("%w: parent %s is not a directory", errFTPTransfer, parent)
				}
				break
			}
		}
	} else {
		return err
	}
	if offset > oldSize {
		return fmt.Errorf("%w: Offset %d is beyond file size %d", errFTPTransfer, offset, oldSize)
	}
	if !connected && offset != 0 {
		return nil
	}
	newSize := int64(len(data))
	if offset > 0 {
		newSize += oldSize + offset
	}
	nextSize := v.used - oldSize + newSize
	if nextSize > ftpVolumeLimit {
		return errors.New("simulated FTP volume is full")
	}
	if offset > 0 {
		existing, err := afero.ReadFile(v, name)
		if err != nil {
			return err
		}
		padded := make([]byte, newSize)
		copy(padded, existing)
		copy(padded[oldSize+offset:], data)
		data = padded
	}
	if err := afero.WriteFile(v, name, data, 0644); err != nil {
		return err
	}
	v.used = nextSize
	return nil
}

func (v *ftpVolume) deleteFile(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	info, err := v.Stat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("not a simulated file")
	}
	if err := v.Remove(name); err != nil {
		return err
	}
	v.used -= info.Size()
	return nil
}

func (v *ftpVolume) renameEntry(from, to string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if from == "" {
		// Without a selected source the reference creates a directory at the destination.
		return v.createRenameDirectory(to)
	}
	if from == "/" || to == "/" || strings.HasPrefix(to, from+"/") {
		return errors.New("invalid simulated rename destination")
	}
	if _, err := v.Stat(from); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	var replacedBytes int64
	if info, err := v.Stat(to); err == nil {
		if info.IsDir() {
			entries, err := afero.ReadDir(v, to)
			if err != nil {
				return err
			}
			if len(entries) != 0 {
				return errors.New("destination directory is not empty")
			}
		} else {
			replacedBytes = info.Size()
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := v.MkdirAll(path.Dir(to), 0755); err != nil {
		return err
	}
	if err := v.Rename(from, to); err != nil {
		return err
	}
	v.used -= replacedBytes
	return nil
}

func (v *ftpVolume) createRenameDirectory(target string) error {
	// A file at the destination or one of its parents is replaced by a
	// directory. Remove it explicitly so the volume releases its bytes.
	for name := target; name != "/"; name = path.Dir(name) {
		info, err := v.Stat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := v.Remove(name); err != nil {
				return err
			}
			v.used -= info.Size()
		}
		break
	}
	return v.MkdirAll(target, 0755)
}

func (v *ftpVolume) deleteDirectory(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if name == "/" {
		return errors.New("cannot remove the simulated volume root")
	}
	info, err := v.Stat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a simulated directory")
	}
	var released int64
	if err := afero.Walk(v, name, func(_ string, info fs.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			released += info.Size()
		}
		return err
	}); err != nil {
		return err
	}
	if err := v.RemoveAll(name); err != nil {
		return err
	}
	v.used -= released
	return nil
}

func ftpDisplaySize(info fs.FileInfo) int64 {
	if info.IsDir() {
		return 42
	}
	return info.Size()
}

func (s *ftpControl) closeData() {
	if s.passive != nil {
		s.passive.Close()
		s.passive = nil
	}
	if s.active != nil {
		s.active.Close()
		s.active = nil
	}
}

func (s *ftpControl) command(session *SessionConnection, command, argument string) (string, error) {
	// The next command consumes the marker, even if it is not a transfer.
	offset := s.restartOffset
	s.restartOffset = 0
	switch command {
	case "PORT", "EPRT", "LPRT", "PASV", "EPSV", "LIST", "NLST", "MLSD", "STAT", "RETR", "STOR", "APPE":
	default:
		return s.reply(command, argument), nil
	}
	if !s.loggedIn {
		return "530 not logged in", nil
	}
	if strings.ContainsAny(argument, "\r\n\x00") {
		return "501 Invalid argument", nil
	}
	switch command {
	case "PASV", "EPSV":
		return s.openPassive(session, command), nil
	case "PORT", "EPRT":
		return s.openActive(session, command, argument), nil
	case "LPRT":
		return s.openLongPort(session, argument), nil
	case "STAT":
		if argument == "" {
			return fmt.Sprintf("211  FTP server status:\nVersion 2.0betaConnected to  (2.0beta)\nLogged in %s\n"+
				"TYPE: ASCII, FORM: Nonprint; STRUcture: File; transfer MODE: Stream\nNo data connection\r\n211 End of status", s.authenticatedUser), nil
		}
	}

	target := s.target(argument)
	preliminary := "150 Data transfer starting"
	var data []byte
	upload := command == "STOR" || command == "APPE"
	hasDataEndpoint := s.passive != nil || s.active != nil
	if hasDataEndpoint {
		offset = max(offset, 0)
	}
	switch command {
	case "LIST", "NLST", "MLSD", "STAT":
		target = s.target(ftpListingArgument(command, argument))
		var directory bool
		var err error
		data, directory, err = s.listing(command, target)
		if err != nil {
			if command == "STAT" {
				return "450 path " + target + " not found", nil
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return "550 File not available", nil
			}
			if command != "LIST" {
				return "550 file does not exist", nil
			}
		}
		if command == "NLST" && !directory {
			return "550 " + argument + " is not a directory", nil
		}
		status := 150
		if command == "STAT" {
			status = 212
			if directory {
				status = 213
			}
		}
		preliminary = fmt.Sprintf("%d Opening ASCII mode data connection for file list", status)
	case "RETR":
		if argument == "" {
			return ftpMissingArgument, nil
		}
		if !hasDataEndpoint {
			info, err := s.files.Stat(target)
			if err != nil {
				return "551 File not available", nil
			}
			remaining := ftpDisplaySize(info) - max(offset, 0)
			reply := fmt.Sprintf("150 Data transfer starting %d bytes", remaining)
			if remaining == 0 || (info.IsDir() && remaining > 0) {
				reply += "\r\n" + ftpTransferSent(0)
			}
			return reply, nil
		}
		s.files.mu.Lock()
		var err error
		data, err = afero.ReadFile(s.files, target)
		s.files.mu.Unlock()
		if err != nil {
			return "551 File not available", nil
		}
		preliminary = fmt.Sprintf("150 Data transfer starting %d bytes", int64(len(data))-offset)
	default: // STOR or APPE.
		if argument == "" {
			return ftpMissingArgument, nil
		}
	}
	if !hasDataEndpoint {
		if !upload {
			return preliminary + "\r\n" + ftpTransferSent(len(data)), nil
		}
		if err := sendFTPReply(session, preliminary); err != nil {
			return "", err
		}
		return s.storeReply(target, nil, offset, false), nil
	}
	defer s.closeData()
	if err := sendFTPReply(session, preliminary); err != nil {
		return "", err
	}
	connection, err := s.transferConnection(session)
	if err != nil {
		return "425 Can't open data connection", nil
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(ftpTransferTimeout)); err != nil {
		return "426 Data connection closed", nil
	}
	if upload {
		data, err = io.ReadAll(io.LimitReader(connection, ftpTransferLimit+1))
		if err != nil {
			return "426 Data connection closed", nil
		}
		if len(data) > ftpTransferLimit {
			return "552 Requested file action aborted", nil
		}
		return s.storeReply(target, data, offset, true), nil
	}
	if command == "RETR" {
		if offset > int64(len(data)) {
			return "551 Error reading file", nil
		}
		data = data[offset:]
	}
	if _, err := connection.Write(data); err != nil {
		return "426 Data connection closed", nil
	}
	return ftpTransferSent(len(data)), nil
}

func (s *ftpControl) storeReply(target string, data []byte, offset int64, connected bool) string {
	if err := s.files.storeFile(target, data, offset, connected); err != nil {
		if errors.Is(err, errFTPTransfer) {
			return "450 " + err.Error()
		}
		return "552 Requested file action aborted"
	}
	if !connected {
		return ""
	}
	return fmt.Sprintf("226 OK, received %d bytes", len(data))
}

func ftpTransferSent(size int) string {
	return fmt.Sprintf("226 Closing data connection, sent %d bytes", size)
}

func (s *ftpControl) transferConnection(session *SessionConnection) (net.Conn, error) {
	if s.active != nil {
		connection := s.active
		s.active = nil
		return connection, nil
	}
	peer, ok := session.Conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("data connection requires a TCP control peer")
	}
	return acceptFTPPeer(s.passive, peer.IP)
}

func (s *ftpControl) openPassive(session *SessionConnection, command string) string {
	s.closeData()
	if session.ListenEphemeralTCP == nil {
		return "425 Can't open data connection"
	}
	listener, err := session.ListenEphemeralTCP()
	if err != nil {
		return "425 Can't open data connection"
	}
	s.passive = listener
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port == 0 {
		s.closeData()
		return "425 Can't open data connection"
	}
	if command == "EPSV" {
		return fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)", addr.Port)
	}
	ip := addr.IP.To4()
	if addr.IP.IsUnspecified() {
		if local, ok := session.Conn.LocalAddr().(*net.TCPAddr); ok {
			ip = local.IP.To4()
		}
	}
	if ip == nil {
		s.closeData()
		return "522 Network protocol not supported"
	}
	return fmt.Sprintf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], addr.Port>>8, addr.Port&255)
}

func acceptFTPPeer(listener net.Listener, expectedIP net.IP) (net.Conn, error) {
	timer := time.AfterFunc(ftpTransferTimeout, func() { listener.Close() })
	defer timer.Stop()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, ok := connection.RemoteAddr().(*net.TCPAddr)
		if ok && peer.IP.Equal(expectedIP) {
			return connection, nil
		}
		connection.Close()
	}
}

func (s *ftpControl) listing(command, target string) (data []byte, directory bool, err error) {
	s.files.mu.Lock()
	defer s.files.mu.Unlock()
	info, err := s.files.Stat(target)
	if err != nil {
		return nil, false, err
	}
	entries := []fs.FileInfo{info}
	if info.IsDir() {
		entries, err = afero.ReadDir(s.files, target)
		if err != nil {
			return nil, false, err
		}
	}
	var out strings.Builder
	for _, entry := range entries {
		kind, indicator := "file", '-'
		if entry.IsDir() {
			kind, indicator = "dir", 'd'
		}
		switch command {
		case "NLST":
			fmt.Fprintf(&out, "%s\r\n", entry.Name())
		case "MLSD":
			fmt.Fprintf(&out, "Type=%s;Modify=%s;Size=%d; %s\n", kind,
				entry.ModTime().Local().Format("20060102150405"), ftpDisplaySize(entry), entry.Name())
		default:
			fmt.Fprintf(&out, "%crwxrwxrwx 1 root root %12d %s %s\r\n", indicator,
				ftpDisplaySize(entry), entry.ModTime().Local().Format("Jan _2 15:04"), entry.Name())
		}
	}
	return []byte(out.String()), info.IsDir(), nil
}

func ftpListingArgument(command, argument string) string {
	if command == "MLSD" || command == "STAT" {
		if argument == "-a" {
			return ""
		}
		return argument
	}
	// LIST and NLST accept leading option words. Keep the rest of the path
	// intact so spaces in file names remain significant.
	for {
		argument = strings.TrimLeft(argument, " ")
		word, rest, _ := strings.Cut(argument, " ")
		if !strings.HasPrefix(word, "-") || strings.ContainsAny(word, "\t\v\f") {
			return argument
		}
		argument = rest
	}
}
