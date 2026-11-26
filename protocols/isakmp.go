package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
)

/*================================================================================
/Protocol: ISAMKMP
/Internet Security Association and Key Management Protocol
/互联网安全关联和密钥管理协议( ISAKMP ) 是由 RFC 2408 定义的协议，用于在互联网环境中建立安全关联
/(SA) 和加密密钥。ISAKMP 仅提供身份验证和密钥交换框架，并且设计为独立于密钥交换；诸如互联网密钥交换
/(IKE) 和Kerberized 互联网密钥协商(KINK) 之类的协议提供了用于 ISAKMP 的经过身份验证的密钥材料
/
/ 备注：Version 等可解析信息未解析
/================================================================================*/

var (
	VENDOR_ID = "12f5f28c457168a9702d9fe274cc0100"
)

// func init() {
// 	AddProtocol(
// 		NewProtocolInfo("isakmp", ISAKMP, 500), ProtocolParams{})
// }

const (
	//	UDP               = "udp"
	PAYLOAD_CODE_VID  = 13
	ISAKMP_HEADER_LEN = 28
)

type ISAKMPHeader struct {
	InitiatorSPI [8]byte
	ResponderSPI [8]byte
	NextPayload  uint8 // Next Payload
	Version      uint8
	ExchangeType uint8  // Exchange Type
	Flags        uint8  // Flags
	MessageID    uint32 // Message ID
	Length       uint32 // Length
}

type ISAKMPPayload struct {
	NextPayload   uint8  // 下一个 Payload 类型
	Reserved      uint8  // 保留字段
	PayloadLength uint16 // Payload 长度
	VendorID      [16]byte
}

func ISAKMP(uc *UDPConnection, b []byte) error {

	// 读取ISAKMP请求数据
	buf := make([]byte, 2048)
	n, raddr, err := uc.ReadFromUDP(buf)
	fmt.Printf("n: %v, raddr: %v\n", n, raddr)
	if err != nil {
		logrus.Errorf("[ISAKMP] Failed to read ISAKMP request: %v", err)
		return nil
	}
	var respData []byte
	// 根据byte长度判断请求头是否为ISAKMP
	if n < ISAKMP_HEADER_LEN {
		logrus.Warnf("[ISAKMP] data too short to be an ISAKMP header")
	} else {
		// 将请求处理成header
		header := &ISAKMPHeader{}
		if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, header); err != nil {
			log.Printf("[ISAKMP] Failed to Decode header : %v", err)
			return nil
		}
		logrus.Printf("[ISAKMP] ISAKMP request header :\n InitiatorSPI: %v,\tResponderSPI: %v,\tNextPayloadCode: %v,\tVersion: %v,\tExchangeTypeCode: %v,\tMsgID: %v\n",
			binary.BigEndian.Uint64(header.InitiatorSPI[:]), binary.BigEndian.Uint64(header.ResponderSPI[:]), header.NextPayload, header.Version, header.ExchangeType, header.MessageID)

		// 	TODO 解析req_payload
		//	由于模拟给nmap的响应只需要header信息，所以暂不解析请求的payload，解析时具体需要根据head里的NextPayload和ExchangeType字段处理成对应的payload

		// 构建ISAKMP响应
		respData, err = buildISAKMPResponse(header)
		if err != nil {
			logrus.Errorf("[ISAKMP] Failed to build ISAKMP response: %v", err)
			return nil
		}

		uc.LogWithRemote("[ISAKMP]  Resolve successfully", uc.RemoteAddr(), logrus.Fields{
			"respData": string(respData),
		})
	}

	_, err = uc.WriteToUDP(respData, raddr)
	if err != nil {
		logrus.Errorf("[ISAKMP] Failed to send ISAKMP response: %v", err)
		return nil
	}

	return nil

}

func buildISAKMPResponse(reqhead *ISAKMPHeader) ([]byte, error) {

	// 构建ISAKMP响应头部
	header := ISAKMPHeader{
		InitiatorSPI: reqhead.InitiatorSPI,
		ResponderSPI: reqhead.ResponderSPI,
		MessageID:    0,
		NextPayload:  PAYLOAD_CODE_VID, //厂商信息payload
		Version:      0,
		ExchangeType: 4, // 2(Main),4(Aggressive),5(Informational,不解析VID信息，ike-version信息拿不到info)
		Flags:        0,
		Length:       48,
	}

	// 构建Paylaod
	payload := ISAKMPPayload{
		NextPayload:   0, // 结束标识
		Reserved:      0,
		PayloadLength: 20,
	}
	copy(payload.VendorID[:], []byte(VENDOR_ID))

	// 写入buf
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logrus.Errorf("[ISAKMP] Failed to encode header: %v", err)
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, payload)
	if err != nil {
		logrus.Errorf("[ISAKMP] Failed to encode payload: %v", err)
		return nil, err
	}

	return buf.Bytes(), nil
}
