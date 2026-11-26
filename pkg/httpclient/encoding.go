package httpclient

import (
	"bytes"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"log"
	"unicode/utf8"
)

func UTF8StringFromEncoding(nameByte []byte, e encoding.Encoding) (value string) {
	value = string(nameByte)
	utf8Reader := transform.NewReader(bytes.NewReader(nameByte), e.NewDecoder())
	all, err := ioutil.ReadAll(utf8Reader)
	if err == nil {
		value = string(all)
	}

	if !utf8.ValidString(value) {
		log.Println("[WARNING] utf8 is not valid")
	}
	return value
}

// 转换编码到UTF，先进行GBK的转换，再进行猜解
func ByteToValidUTF8(dataByte []byte) (value string) {
	value = string(dataByte)

	// 考虑编码的问题，要转换为utf8
	if !utf8.ValidString(value) {
		value = UTF8StringFromEncoding(dataByte, simplifiedchinese.GBK)
		if utf8.ValidString(value) {
			return
		}

		determineEncoding, _, _ := charset.DetermineEncoding(dataByte, "")
		value = UTF8StringFromEncoding(dataByte, determineEncoding)
		if utf8.ValidString(value) {
			return
		}
	}
	return
}
