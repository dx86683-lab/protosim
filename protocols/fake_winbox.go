package protocols

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

/*================================================================================
/Protocol: WinBox
/
/该伪造程序仅实现winbox协议号为：02（FileContainer），06（?UninstallScript）的相关协议交互
/02号协议是目前几乎所有Winbox资产存活性探测所使用的协议
/06号协议是现在网络存活的绝大部分RouterOS设备使用的主要通讯协议，涵盖登录验证、设备配置等
/06号协议该程序仅实现登录验证过程的部分交互
/
/备注：解析了6.XX的版本，没有解析7.XX的版本
/版本号：
/				6.48.3     6.49.6   6.47.8
/				6.47.7     6.6      6.49.8
/				6.49.10    6.43.8   等
/params
/   1: index 数据 有具体格式
/   2: list  数据 无具体格式
/================================================================================*/

var (
	// 变量均按照 协议名称_用途 格式进行命名以免与后续其他协议产生冲突

	WINBOX_SERVER_VERSION  = "6.49.6"
	WINBOX_MAX_BUFFER_SIZE = 1024 * 4

	WINBOX_NULL              = byte('\x00')
	WINBOX_FILE_MODE         = uint8('\x02')
	WINBOX_LEGACY_LOGIN_MODE = uint8('\x05')
	WINBOX_LOGIN_MODE        = uint8('\x06')

	WINBOX_FileResponseIndexPrefix = "ff02696e646578000000ff02696e64657800000000000001017a00000000" // Index Prefix 	//List Prefix
	WINBOX_FileResponseIndexBody   = `3962351248 31787 advtool.dll 6.49.6
2679504116 39401 secure.dll 6.49.6
3447322526 39627 dhcp.dll 6.49.6
3733112359 43968 ppp.dll 6.49.6
1763829997 55389 roting4.dll 6.49.6
3448921101 39311 mpls.dll 6.49.6
3423247868 39572 hotspot.dll 6.49.6
3665498732 79806 wlan6.dll 6.49.6
969507780 41761 ipv6.dll 6.49.6
`

	WINBOX_FileResponseEmpty = StringToBytes("1302000000000000000000000002ffff0000000001") // 空解析数据 不做处理
	WINBOX_FileResponseIndex = StringToBytes("ff02696e64657800000000000001017a000000003339363233353132343820333137383720616476746f6f6c2e646c6c20362e34392e360a32363739353034313136203339343031207365637572652e646c6c20362e34392e360a3334343733323235323620333936323720646863702e646c6c20362e34392e360a33373333313132333539203433393638207070702e646c6c20362e34392e360a3137363338323939393720353533383920726f74696e67342e646c6c20362e34392e360a33343438393231313031203339333131206d706c732e646c6c20362e34392e360a3334323332343738363820333935373220686f7473706f742e646c6c20362e348dff392e360a3336363534393837333220373938303620776c616e362e646c6c20362e34392e360a39363935303737383020343137363120697076362e646c6c20362e34392e360a333834353431323934302037353231373420726f7465726f732e646c6c20362e34392e360a3336393139313233313520323534312073797374656d2e646c6c20362e34392e360a")
	WINBOX_FileResponseList  = StringToBytes("ff026c697374000000000000000104c1000000007b206372633a203636313239393337372c2073697a653a20313335302c206e616d653a2022616476746f6f6c2e6a67222c20756e697175653a2022616476746f6f6c2d3363353030663133333538372e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a203530323939373036302c2073697a653a20343233392c206e616d653a20227365637572652e6a67222c20756e697175653a20227365637572652d3630313564613864323731662e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20313136323536393138332c2073697a653a203335ffff37352c206e616d653a2022646863702e6a67222c20756e697175653a2022646863702d3663313533343930346465302e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20333934393435353235302c2073697a653a20343539352c206e616d653a20227070702e6a67222c20756e697175653a20227070702d3631383266326536313264302e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20333437363639323132392c2073697a653a20383239302c206e616d653a2022726f74696e67342e6a67222c20756e697175653a2022726f74696e67342d3263336131356263326563622e6affff67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a203934373631323936362c2073697a653a20333634372c206e616d653a20226d706c732e6a67222c20756e697175653a20226d706c732d6433616235656639623934362e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20333038333136373232372c2073697a653a20343139302c206e616d653a2022686f7473706f742e6a67222c20756e697175653a2022686f7473706f742d3561653931663331393632652e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20323032333035383830352c2073697a65ffff3a2031393031312c206e616d653a2022776c616e362e6a67222c20756e697175653a2022776c616e362d6431653364316232643066382e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20313633373032353030342c2073697a653a20363533342c206e616d653a2022697076362e6a67222c20756e697175653a2022697076362d6539353937323635356238352e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a7b206372633a20323139393032363734372c2073697a653a2031363633382c206e616d653a202269636f6e732e706e67222c2076657273696f6e3a2022362e34392e3622207d2c0a7bd7ff206372633a20323038343538343133352c2073697a653a2032373130342c206e616d653a202269636f6e7332342e706e6722207d2c0a7b206372633a203733363238383037342c2073697a653a2033383230352c206e616d653a202269636f6e7333322e706e6722207d2c0a7b206372633a203130373437313235362c2073697a653a2037323032362c206e616d653a2022726f7465726f732e6a67222c20756e697175653a2022726f7465726f732d3632336436386362393333392e6a67222c2076657273696f6e3a2022362e34392e3622207d2c0a")

	// Login失败的响应格式固定 不做变化
	WINBOX_LoginResponseFirst       = StringToBytes("210600a099cfc66e2fda2739993955b0a671663b55e08585c9a14d583e81fb9661e100")
	WINBOX_LoginResponseLoginFailed = StringToBytes("2106696e76616c69642075736572206e616d65206f722070617373776f726420283629") // 解析结果为：!invalid user name or password (6)

	errorsInvalidRequest       = errors.New("invalid request")
	errorsInvalidFileRequest   = errors.New("invalid file request")
	errorsNotSupportRequestMod = errors.New("not support request mod")
)

type WinboxRequest struct {
	length  uint8
	mode    uint8
	payload []byte
}
type FileRequest struct {
	FileName  string
	SkipSize  uint16
	ReplySize uint16
}

//func init() {
//	AddProtocol(
//		NewProtocolInfo("winbox", WinBox, 8291),
//		ProtocolParams{ // index 响应
//			Name:         "file_response_body",
//			DefaultValue: WINBOX_FileResponseIndexBody,
//		},
//		ProtocolParams{
//			Name:         "version",
//			DefaultValue: WINBOX_SERVER_VERSION,
//		})
//}

func WinBox(lc *ListenConnection) error {
	for {
		conn, err := lc.Listener.Accept()
		if err != nil {
			logrus.Warnf("[Winbox] ListenAndServe err:%s", err)
			continue
		}
		buf, err := WinboxRead(conn, WINBOX_MAX_BUFFER_SIZE)
		if err == io.EOF {
			continue
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed") {
				return err
			}
			logrus.Warnf("[Winbox] Read buffer err:%s", err)
			continue
		}
		// 解析请求
		req, err := ParseRequest(buf)
		if err != nil {
			logrus.Errorf("[Winbox] ParseRequest err:%v", err)
			err = conn.Close()
			if err != nil {
				return err
			}
			return err
		}
		// 构造响应
		var localAddr = conn.LocalAddr()
		var remoteAddr = conn.RemoteAddr()
		switch req.mode {
		// mode 1
		case WINBOX_FILE_MODE:
			fileRequest, err := parseFileRequest(req.payload)
			if err != nil {
				return err
			}
			logrus.Infof("[Winbox] %s->%s file request , filename: %s", remoteAddr, localAddr, fileRequest.FileName)
			switch fileRequest.FileName {
			case "index":
				//reply(conn, WINBOX_FileResponseIndex, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))

				_, err = conn.Write([]byte(WINBOX_FileResponseIndexPrefix + WINBOX_FileResponseIndexBody))
			case "list":
				reply(conn, WINBOX_FileResponseList, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))
			case "":
				reply(conn, WINBOX_FileResponseList, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))
			default:
				reply(conn, WINBOX_FileResponseEmpty, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))
			}
			// mode 2
		case WINBOX_LOGIN_MODE:
			if index := bytes.IndexByte(req.payload, WINBOX_NULL); len(req.payload)-index == 34 {
				logrus.Infof("[Winbox] login mode : %s->%s login request , username: %s", remoteAddr, localAddr, string(req.payload[:index]))
				reply(conn, WINBOX_LoginResponseFirst, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))
			} else {
				reply(conn, WINBOX_LoginResponseLoginFailed, []byte(lc.GetStringParams("version", WINBOX_SERVER_VERSION)))
			}
		// 默认
		default:
			lc.LogWithRemote("[Winbox] unrecognized request mode", remoteAddr, logrus.Fields{
				"length":  req.length,
				"mode":    req.mode,
				"payload": string(req.payload),
			})
			//fmt.Println(req.length, req.mode, req.payload)
			if err != nil {
				logrus.Errorf("[Winbox] serve: ReplyForgeryResponse err %v", err)
			}
			return errorsNotSupportRequestMod
		}
	}
}

func WinboxRead(conn net.Conn, size int) (buf []byte, err error) {

	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	return buf, err
}

func parseFileRequest(payload []byte) (*FileRequest, error) {
	if len(payload) != 18 {
		return nil, errorsInvalidFileRequest
	}
	r := &FileRequest{}
	if index := bytes.IndexByte(payload, byte(WINBOX_NULL)); index == -1 {
		return nil, errorsInvalidFileRequest
	} else {
		r.FileName = string(payload[:index])
	}
	r.ReplySize = BytesToUint16(payload[12:14])
	r.SkipSize = BytesToUint16(payload[16:18])
	return r, nil
}

func reply(conn net.Conn, buf []byte, version []byte) error {
	buf = replaceResponse(buf, []byte(WINBOX_SERVER_VERSION), version)
	_, err := conn.Write(buf)
	return err
}

func replaceResponse(buf, old, new []byte) []byte {
	buf = bytes.ReplaceAll(buf, old, new)
	buf[0] = byte(len(buf) - 2)
	return buf
}

func BytesToUint16(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

func StringToBytes(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		logrus.Fatal(err)
	}
	return buf
}

func ParseRequest(buf []byte) (*WinboxRequest, error) {
	if len(buf) < 2 {
		return nil, errorsInvalidRequest
	}
	if len(buf)-2 != int(buf[0]) {
		return nil, errorsInvalidRequest
	}
	if buf[1] > 0x18 || buf[1] < 0x01 {
		return nil, errorsInvalidRequest
	}
	return &WinboxRequest{buf[0], buf[1], buf[2:]}, nil
}
