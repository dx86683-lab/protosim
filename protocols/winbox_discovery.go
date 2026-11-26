package protocols

import (
	"errors"
	"io"
	"strings"
	"time"
)

const winboxIndexHeaderSize = 20

var winboxDefaultIndexBody = strings.TrimSuffix(WINBOX_FileResponseIndexBody, "\n")

func init() {
	AddProtocol(NewProtocolInfo("winbox", serveWinboxDiscovery, 8291),
		ProtocolParams{Name: "file_response_body", DefaultValue: winboxDefaultIndexBody},
		ProtocolParams{Name: "version", DefaultValue: WINBOX_SERVER_VERSION})
}

func serveWinboxDiscovery(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	version := session.GetStringParams("version", WINBOX_SERVER_VERSION)
	body := session.GetStringParams("file_response_body", winboxDefaultIndexBody)
	if len(version) > 64 || strings.ContainsAny(version, "\r\n\x00") || len(body) > WINBOX_MAX_BUFFER_SIZE {
		return errors.New("invalid Winbox discovery metadata")
	}

	indexBody := strings.ReplaceAll(body, WINBOX_SERVER_VERSION, version)
	if len(indexBody) > WINBOX_MAX_BUFFER_SIZE {
		return errors.New("expanded Winbox index exceeds metadata limit")
	}
	index := make([]byte, winboxIndexHeaderSize+len(indexBody))
	copy(index, WINBOX_FileResponseIndex[:winboxIndexHeaderSize])
	copy(index[winboxIndexHeaderSize:], indexBody)
	list := replaceResponse(WINBOX_FileResponseList, []byte(WINBOX_SERVER_VERSION), []byte(version))
	for {
		var header [2]byte
		if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
			return err
		}
		if header[0] != 18 || header[1] != WINBOX_FILE_MODE {
			return nil
		}
		var payload [18]byte
		if _, err := io.ReadFull(session.Conn, payload[:]); err != nil {
			return err
		}
		request, err := parseFileRequest(payload[:])
		if err != nil {
			return err
		}
		reply := WINBOX_FileResponseEmpty
		switch request.FileName {
		case "index":
			reply = index
		case "list", "":
			reply = list
		}
		if _, err := session.Conn.Write(reply); err != nil {
			return err
		}
	}
}
