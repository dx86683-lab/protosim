package protocols

import (
	"bytes"
	"errors"
	"regexp"
)

// rrp对应全局的数据结构， sessionBindData对应回话数据， req对应一个当前处理的消息
type RespFunction func(rrp *ReqRespProcessor, sessionBindData interface{}, req interface{}) ([]byte, error)

type ReqRespHandler struct {
	Match        string
	MatchType    string // contains/regex/begin_with/end_with/equal
	MatchRegex   *regexp.Regexp
	RespFunction RespFunction
}

type CheckValueFunction func(req interface{}) []byte
type ReqRespProcessor struct {
	MessageSplitor  MessageSplitor          // 消息切割器，默认是接受1024字节长度的消息，可以是以字符串分隔
	Handlers        []ReqRespHandler        // 处理列表，有顺序关系
	DefaultFunc     RespFunction            // 所有输入都不匹配情况下的处理程序，如果没有，就会断开
	ValueToCheck    CheckValueFunction      // 提取检查的字段
	BindGlobalData  interface{}             //全局绑定的对象，由各协议自实现
	InitSessionData func(data *interface{}) //会话绑定的数据
}

func DoBasicReqResp(sc *SessionConnection, h ReqRespProcessor) error {
	defer sc.DeleteActivity()
	//log.printf("new connection from %s", sc.Conn.RemoteAddr())

	// 初始化回话信息
	var sessionBindData interface{}
	if h.InitSessionData != nil {
		h.InitSessionData(&sessionBindData)
	}

	for {
		var data interface{}
		var valueToCheck []byte
		if h.MessageSplitor == nil {
			buf := make([]byte, 1024)
			if n, err := sc.Conn.Read(buf); err == nil {
				data = buf[:n]
				valueToCheck = buf[:n]
			} else {
				return err
			}
		} else {
			if d, err := h.MessageSplitor(sc); err == nil {
				data = d
				if h.ValueToCheck != nil {
					valueToCheck = h.ValueToCheck(data)
				}
			} else {
				return err
			}
		}

		var doHandler RespFunction
	matchLoop:
		for i := range h.Handlers {
			hdl := &h.Handlers[i]
			switch hdl.MatchType {
			case "regex":
				if hdl.MatchRegex == nil {
					var err error
					hdl.MatchRegex, err = regexp.Compile(hdl.Match)
					if err != nil {
						return err
					}
				}
				if hdl.MatchRegex.Match(valueToCheck) {
					doHandler = hdl.RespFunction
					break matchLoop
				}
			case "equal":
				if bytes.Equal(valueToCheck, []byte(hdl.Match)) {
					doHandler = hdl.RespFunction
					break matchLoop
				}
			}
		}

		if doHandler == nil {
			// 默认处理流程
			if h.DefaultFunc == nil {
				return errors.New("[WARNING] not default response function, close connection")
			}
			doHandler = h.DefaultFunc
		}

		if buf, err := doHandler(&h, sessionBindData, data); err != nil {
			if len(buf) > 0 {
				sc.Conn.Write(buf)
			}
			return err
		} else {
			if _, err := sc.Conn.Write(buf); err != nil {
				return err
			}
		}
	}
}
