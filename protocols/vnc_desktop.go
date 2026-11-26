package protocols

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"time"
)

const (
	vncDesktopWidth  = 800
	vncDesktopHeight = 600
	vncFrameInterval = 200 * time.Millisecond
	vncWriteTimeout  = 5 * time.Second
)

func serveVNCDesktop(conn net.Conn) error {
	var clientInit [1]byte
	if _, err := io.ReadFull(conn, clientInit[:]); err != nil {
		return err
	}
	// The reference uses 32 bits per pixel with a 24-bit color depth.
	const serverInit = "\x03\x20\x02\x58\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00\x00\x00\x00\x00\x00\x00\x00"
	if _, err := io.WriteString(conn, serverInit); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	requested, finished := make(chan struct{}), make(chan error, 1)
	go func() { finished <- readVNCControls(conn, requested) }()
	select {
	case <-requested:
	case err := <-finished:
		return err
	}

	frame := make([]byte, 16+4*vncDesktopWidth*vncDesktopHeight)
	frame[3] = 1
	binary.BigEndian.PutUint16(frame[8:10], vncDesktopWidth)
	binary.BigEndian.PutUint16(frame[10:12], vncDesktopHeight)
	ticker := time.NewTicker(vncFrameInterval)
	defer ticker.Stop()
	capture, _ := conn.(interface{ FlushCapturedResponse() })
	for phase := 0; ; phase += 2 {
		select {
		case <-ticker.C:
		case err := <-finished:
			return err
		}
		fillVNCPixels(frame[16:], phase)
		if err := conn.SetWriteDeadline(time.Now().Add(vncWriteTimeout)); err != nil {
			return err
		}
		if _, err := conn.Write(frame); err != nil {
			return err
		}
		if capture != nil {
			capture.FlushCapturedResponse()
		}
	}
}

func readVNCControls(conn net.Conn, requested chan struct{}) error {
	var header [8]byte
	for {
		if _, err := io.ReadFull(conn, header[:1]); err != nil {
			return err
		}
		kind := header[0]
		var remaining int64
		switch kind {
		case 0: // SetPixelFormat
			remaining = 19
		case 2: // SetEncodings
			if _, err := io.ReadFull(conn, header[:3]); err != nil {
				return err
			}
			remaining = int64(binary.BigEndian.Uint16(header[1:3])) * 4
		case 3: // FramebufferUpdateRequest
			remaining = 9
		case 4: // KeyEvent
			remaining = 7
		case 5: // PointerEvent
			remaining = 5
		case 6: // ClientCutText
			if _, err := io.ReadFull(conn, header[:7]); err != nil {
				return err
			}
			remaining = int64(binary.BigEndian.Uint32(header[3:7]))
			if remaining > 1<<16 {
				return errors.New("VNC clipboard message exceeds limit")
			}
		default:
			return errors.New("unsupported VNC desktop message")
		}
		if _, err := io.CopyN(io.Discard, conn, remaining); err != nil {
			return err
		}
		if kind == 3 && requested != nil {
			close(requested)
			requested = nil
		}
	}
}

// Adapted from the MIT-licensed go-rfb server example. See LICENSE.go-rfb.
// https://github.com/unistack-org/go-rfb/blob/d732f3a88aed8a77cf2344d0bb2b6d33e2f318fd/example/server/main.go
func fillVNCPixels(pixels []byte, phase int) {
	const border = 50
	var near, far [vncDesktopWidth]int
	for i := range near {
		angle := float64(i+phase*2) / 40
		near[i] = int((1.1 + math.Sin(angle)) * border)
		far[i] = int((1.1 + math.Sin(math.Pi+angle)) * border)
	}
	pos := 0
	for y := range vncDesktopHeight {
		for x := range vncDesktopWidth {
			var red, green, blue byte
			switch {
			case x < near[y]:
				red = 255
			case x > vncDesktopWidth-far[y]:
				green = 255
			case y < near[x]:
				red, green = 255, 255
			case y > vncDesktopHeight-far[x]:
				blue = 255
			default:
				red, green, blue = byte(x+phase), byte(y+phase), byte(x+y+phase*3)
			}
			pixels[pos], pixels[pos+1], pixels[pos+2] = blue, green, red
			pos += 4
		}
	}
}
