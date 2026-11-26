package encoding

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/axgle/mahonia"
)

func UTF8(resp *http.Response, body string) (s string) {
	s = body
	if len(s) < 1 {
		return
	}

	encoding := Guess(resp, body)

	if encoding == "utf-8" {
		return
	}

	if len(encoding) == 0 || encoding == "none" {
		encoding = "utf-8"
	}

	defer func() {
		if r := recover(); r != nil {
			log.Panicf("编码转换失败: %s, %s", encoding, s)
			panic(r)
		}
	}()

	enc := mahonia.NewDecoder(encoding)
	if enc == nil {
		enc = mahonia.NewDecoder("utf-8")
	}

	s = enc.ConvertString(body)
	return
}

var regMeta = regexp.MustCompile(`(?i:<meta[^>]+charset=['"]?([\w\-]+)[^>]*?>)`)

func getEncodingFromBody(body string) string {
	result := regMeta.FindStringSubmatch(body)
	if len(result) < 2 {
		return ""
	}
	encoding := result[1]
	if len(encoding) == 0 {
		return ""
	}
	return strings.ToLower(encoding)
}

var regCharset = regexp.MustCompile(`charset=['"]?([\w\-]+)['"]?`)

func getEncodingFromHeader(header http.Header) string {
	contentType := header.Get("Content-Type")
	if contentType == "" {
		return ""
	}
	result := regCharset.FindStringSubmatch(contentType)
	if len(result) < 2 {
		return ""
	}
	encoding := result[1]
	if len(encoding) == 0 {
		return ""
	}
	return strings.ToLower(encoding)
}

func guess(resp *http.Response, body string) string {
	encoding := getEncodingFromHeader(resp.Header)
	if encoding != "" && encoding != "none" {
		return encoding
	}
	encoding = getEncodingFromBody(body)
	if encoding != "" {
		return encoding
	}
	return "utf-8"
}

func Guess(resp *http.Response, body string) string {
	encoding := guess(resp, body)
	if encoding == "gb2312" {
		return "gbk"
	} else if encoding == `%s` {
		return "utf-8"
	} else if encoding == "plain" {
		return "utf-8"
	}
	return encoding
}
