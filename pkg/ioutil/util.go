package ioutil

import (
	"bytes"
	"encoding/binary"

	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// UTF16BytesToString converts UTF-16 encoded bytes, in big or little endian byte order,
// to a UTF-8 encoded string.
func UTF16BytesToString(b []byte, o binary.ByteOrder) string {
	utf := make([]uint16, (len(b)+(2-1))/2)
	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = o.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}
	return string(utf16.Decode(utf))
}

func UTF8StringToUTF16Bytes(s string, o binary.ByteOrder) []byte {
	runes := utf16.Encode([]rune(s))
	bs := make([]byte, len(runes)*2)
	for i, r := range runes {
		start := i * 2
		end := start + 2
		o.PutUint16(bs[start:end], r)
	}
	return bs
}

func ReadBytes(len int, r io.Reader) ([]byte, error) {
	b := make([]byte, len)
	length, err := io.ReadFull(r, b)
	return b[:length], err
}

// 读取直到遇到结束字节串
func ReadUntil(endbs []byte, r io.Reader) ([]byte, error) {
	buf := []byte{}
	readLen := len(endbs)
	for {
		b, err := ReadByte(r)
		if err != nil {
			return buf, err
		}
		buf = append(buf, b)
		startPos := len(buf) - readLen
		if startPos < 0 {
			startPos = 0
		}
		bs := buf[startPos:]
		if bytes.Equal(bs, endbs) {
			break
		}
	}
	return buf, nil
}

func BytesToCStr(bs []byte, unicode bool) (string, error) {
	len := len(bs)
	if unicode {
		last := len
		for i := len; i > 0; i -= 2 {
			if bs[i-1] != 0 || bs[i-2] != 0 {
				last = i
				break
			}
		}
		return UTF16BytesToString(bs[:last], binary.LittleEndian), nil
	} else {
		last := len
		for i := len; i > 0; i-- {
			if bs[i-1] != 0 {
				last = i
				break
			}
		}
		return string(bs[:last]), nil
	}
}

// 读取cstring，
// len: 读取的字节长度，包含\0结束符
// unicode: 是否为unicode(utf16)编码
func ReadCStringLen(len int, unicode bool, r io.Reader) (string, error) {
	if len <= 0 {
		return "", nil
	}
	bs, err := ReadBytes(len, r)
	if err != nil {
		return "", err
	}
	return BytesToCStr(bs, unicode)
}

// 读取\0结尾的cstring，
// unicode: 是否为unicode(utf16)编码
// 返回读取的字符串，读取长度，错误
func ReadCString(unicode bool, r io.Reader) (string, int, error) {
	endMark := []byte{0}
	if unicode {
		// unicode使用两个0字节表示结束
		endMark = []byte{0, 0}
	}
	bs, err := ReadUntil(endMark, r)
	if err != nil || len(bs) <= len(endMark) {
		return "", len(bs), err
	}

	rs, err := BytesToCStr(bs, unicode)
	return rs, len(bs), err
}

// 读取string，
// len: 读取的字节长度，
// unicode: 是否为unicode(utf16)编码
func ReadString(len int, unicode bool, r io.Reader) (string, error) {
	if len <= 0 {
		return "", nil
	}
	bs, err := ReadBytes(len, r)
	if err != nil {
		return "", err
	}
	if unicode {
		return UTF16BytesToString(bs, binary.LittleEndian), nil
	} else {
		return string(bs), nil
	}
}

func ReadByte(r io.Reader) (byte, error) {
	b, err := ReadBytes(1, r)
	if err != nil {
		return 0, err
	}
	return b[0], err
}

func ReadUInt8(r io.Reader) (uint8, error) {
	b, err := ReadBytes(1, r)
	if err != nil {
		return 0, err
	}
	return uint8(b[0]), err
}

func ReadUint16LE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func ReadUint16BE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func ReadUInt32LE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func ReadUInt32BE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func WriteByte(data byte, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func WriteBytes(data []byte, w io.Writer) (int, error) {
	return w.Write(data)
}

// 写入cstring,自动添加\0结束符
func WriteCString(s string, unicode bool, w io.Writer) (int, error) {
	if unicode {
		end := []byte{0, 0}
		bs := UTF8StringToUTF16Bytes(s, binary.LittleEndian)
		bs = append(bs, end...)
		return WriteBytes(bs, w)
	} else {
		end := []byte{0}
		b := append([]byte(s), end...)
		return WriteBytes(b, w)
	}
}

// 写入string
func WriteString(s string, unicode bool, w io.Writer) (int, error) {
	if unicode {
		bs := UTF8StringToUTF16Bytes(s, binary.LittleEndian)
		return WriteBytes(bs, w)
	} else {
		return WriteBytes([]byte(s), w)
	}
}

func WriteUInt8(data uint8, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func WriteUInt16BE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return w.Write(b)
}

func WriteUInt16LE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, data)
	return w.Write(b)
}

func WriteUInt32LE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, data)
	return w.Write(b)
}

func WriteUInt32BE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return w.Write(b)
}
