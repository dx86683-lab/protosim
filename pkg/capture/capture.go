//go:build cgo

package capture

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/protocols"
)

func printDevs() {
	fmt.Println("supported devices:")
	devs, _ := pcap.FindAllDevs()
	for _, dev := range devs {
		fmt.Println(dev.Name, "   ", dev.Description, " addresses: ")
		for _, addr := range dev.Addresses {
			fmt.Println("    ", addr.IP.String())
		}
	}
}

func quoteAscii(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strconv.QuoteToASCII(s), "\""), "\"")
}

func LogUDP(devName string, log *logrus.Logger) {
	handle, err := pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		printDevs()
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter("udp and not (src net 127.0.0.0/8)"); err != nil {
		panic(err)
	}

	logrus.Infof("[UDPLogger] running on %s device", devName)
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		ip := pkt.NetworkLayer()
		udp := pkt.TransportLayer()
		if ip != nil && udp != nil {
			sip := net.ParseIP(ip.NetworkFlow().Src().String())
			sport, err := strconv.Atoi(udp.TransportFlow().Src().String())
			if err != nil {
				logrus.Errorf("[UDPLogger] convert src port error: %v.", err)
				continue
			}
			saddr := net.UDPAddr{
				IP:   sip,
				Port: sport,
			}

			if protocols.IsExclusion(&saddr) {
				logrus.Info("[UDPLogger] skip addr:", saddr)
				continue
			}

			dport, err := strconv.Atoi(udp.TransportFlow().Dst().String())
			if err != nil {
				logrus.Errorf("[UDPLogger] convert dst port error: %v.", err)
				continue
			}
			local_addr := ip.NetworkFlow().Dst().String() + ":" + udp.TransportFlow().Dst().String()

			data := udp.LayerPayload()
			fields := protocols.BuildRemoteInfo(&saddr, map[string]interface{}{
				"local":       local_addr,
				"local_port":  dport,
				"request_raw": hex.EncodeToString(data),
				"request":     quoteAscii(string(data)),
			})
			log.WithFields(fields).Info("udp_packet")
		}

	}
}

func LogICMP(devName string, log *logrus.Logger) {
	handle, err := pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		printDevs()
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter("icmp[icmptype] == icmp-echo and not (src net (169.254/16 or 127.0.0.0/8))"); err != nil {
		panic(err)
	}

	logrus.Infof("[ICMPLogger] running on %s device", devName)
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for pkt := range packets {
		ip := pkt.NetworkLayer()
		if ip != nil {
			sip := ip.NetworkFlow().Src().String()

			if protocols.IsExclusionIP(sip) {
				logrus.Info("[ICMPLogger] skip ip:", sip)
				continue
			}

			local_addr := ip.NetworkFlow().Dst().String()

			fields := map[string]interface{}{
				"remote_ip": sip,
				"local":     local_addr,
				"host":      protocols.GetLogHostName(),
			}
			log.WithFields(fields).Info("icmp_ping")
		}
	}
}

func LogSYN(devName string, log *logrus.Logger) {
	handle, err := pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		printDevs()
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0 and not (src net 127.0.0.0/8)"); err != nil {
		panic(err)
	}

	logrus.Infof("[SYNLogger] running on %s device", devName)
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		ip := pkt.NetworkLayer()
		tcp := pkt.TransportLayer()
		if ip != nil && tcp != nil {
			sip := net.ParseIP(ip.NetworkFlow().Src().String())
			sport, err := strconv.Atoi(tcp.TransportFlow().Src().String())
			if err != nil {
				logrus.Errorf("[SYNLogger] convert src port error: %v.", err)
				continue
			}
			saddr := net.TCPAddr{
				IP:   sip,
				Port: sport,
			}

			if protocols.IsExclusion(&saddr) {
				logrus.Info("[SYNLogger] skip addr:", saddr)
				continue
			}

			dport, err := strconv.Atoi(tcp.TransportFlow().Dst().String())
			if err != nil {
				logrus.Errorf("[SYNLogger] convert dst port error: %v.", err)
				continue
			}
			local_addr := ip.NetworkFlow().Dst().String() + ":" + tcp.TransportFlow().Dst().String()

			fields := protocols.BuildRemoteInfo(&saddr, map[string]interface{}{
				"local":      local_addr,
				"local_port": dport,
			})
			log.WithFields(fields).Info("tcp_syn")
		}

	}
}
