package tun

import "io"

// writeSinglePacket converts WireGuard's packet count to the io.Writer byte count.
func writeSinglePacket(write func([][]byte, int) (int, error), packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	n, err := write([][]byte{packet}, 0)
	if n == 1 {
		return len(packet), err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	return 0, err
}
