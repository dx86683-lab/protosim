package protocols

import (
	"bufio"
	"bytes"
)

type MessageSplitor func(sc *SessionConnection) (interface{}, error)

// 行提取
func LineMessageSplitor() MessageSplitor {
	return func(sc *SessionConnection) (interface{}, error) {
		msg, err := bufio.NewReader(sc.Conn).ReadBytes('\n')
		return msg, err
	}
}

// 行提取，同时进行trim空白字符的操作
func LineTrimMessageSplitor() MessageSplitor {
	return func(sc *SessionConnection) (interface{}, error) {
		msg, err := LineMessageSplitor()(sc)
		if err == nil {
			msg = bytes.Trim(msg.([]byte), " \t\r")
		}
		return msg, err
	}
}
