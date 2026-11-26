// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris

/*
 * Copyright (c) 2015, fromkeith
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * * Neither the name of the fromkeith nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package gossdp

import (
	"errors"
	"net"

	"golang.org/x/net/ipv4"
)

type theSocket struct {
	rawSocket net.PacketConn
	socket    *ipv4.PacketConn
	readBytes []byte
}

func (ts theSocket) IsValid() bool {
	return ts.socket != nil
}

func (ts theSocket) Create() error {
	group := net.IPv4(239, 255, 255, 250)
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	con, err := net.ListenPacket("udp4", "0.0.0.0:1900")
	if err != nil {
		return err
	}
	p := ipv4.NewPacketConn(con)
	p.SetMulticastLoopback(true)
	didFindInterface := false
	for _, v := range interfaces {
		ef, err := v.Addrs()
		if err != nil {
			continue
		}
		hasRealAddress := false
		for k := range ef {
			asIp := net.ParseIP(ef[k].String())
			if asIp.IsUnspecified() {
				continue
			}
			hasRealAddress = true
			break
		}
		if !hasRealAddress {
			continue
		}
		err = p.JoinGroup(&v, &net.UDPAddr{IP: group})
		if err != nil {
			continue
		}
		didFindInterface = true
	}
	if !didFindInterface {
		return errors.New("Unable to find a compatible network interface!")
	}
	ts.socket = p
	ts.rawSocket = con
	ts.readBytes = make([]byte, 2048)
	return nil
}

func (ts *theSocket) Close() {
	ts.socket.Close()
	ts.rawSocket.Close()
	ts.rawSocket = nil
}

func (ts *theSocket) Read() ([]byte, string, error) {
	n, src, err := ts.rawSocket.ReadFrom(ts.readBytes)
	if err != nil {
		return nil, "", err
	}
	if n > 0 {
		return ts.readBytes[0:n], src.String(), nil
	}
	return nil, "", nil
}

func (ts *theSocket) Write(msg WriteMessage) error {
	_, err := ts.rawSocket.WriteTo(msg.Message, msg.To)
	return err
}
