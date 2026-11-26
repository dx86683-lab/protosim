package goutils

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/google/uuid"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"regexp"
	"strings"
	"time"
)

// StringSliceContains 确认字符列表包含元素
func StringSliceContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Ints returns a unique subset of the int slice provided.
func UniqStrings(input []string) []string {
	u := make([]string, 0, len(input))
	m := make(map[string]bool)

	for _, val := range input {
		if _, ok := m[val]; !ok {
			m[val] = true

			// 有内容才算
			if len(val) > 0 {
				u = append(u, val)
			}
		}
	}

	return u
}

// GetStringInBetween Returns empty string if no start string found
func GetStringInBetween(str string, start string, end string) (result string) {
	//没有起始字符，说明直接从开头开始
	if len(str) > 0 {
		s := strings.Index(str, start)
		if s == -1 {
			return
		}
		s += len(start)
		str = str[s:]
	}

	//没有终止字符，说明直接到末尾
	if len(end) == 0 {
		return str
	}

	e := strings.Index(str, end)
	if e == -1 { //没有结束就是到末尾
		e = len(str)
	}
	return str[:e]
}

/*
mode:
0 AAA -> 414141
1 AAA -> 0x414141
2 AAA -> \x41\x41\x41
3 AAA -> 41 41 41
*/
func ToHex(str string, mode int) string {
	switch mode {
	default:
		return hex.EncodeToString([]byte(str))
	case 1:
		return "0x" + ToHex(str, 0)
	case 2:
		retStr := ""
		newStr := ToHex(str, 0)
		for i := 0; i < len(newStr)/2; i++ {
			retStr += `\x` + newStr[2*i:2*(i+1)] // slice怎么取部分？
		}
		return retStr
	case 3:
		var retStrArray []string
		newStr := ToHex(str, 0)
		for i := 0; i < len(newStr)/2; i++ {
			retStrArray = append(retStrArray, newStr[2*i:2*(i+1)])
		}
		return strings.Join(retStrArray, " ")
	}
}

// shell执行参数时，用双引号括起来了，需要进行转义
// \ 和 "
func ShellDoubleQuoteEscape(str string) string {
	str = strings.ReplaceAll(str, `\`, `\\`)
	str = strings.ReplaceAll(str, `"`, `\"`)
	return str
}

// 随机生成指定长度的字符串
func RandomHexString(size int) (ret string) {
	md5hash := md5.New()
	md5hash.Write([]byte(time.Now().String()))
	base := ToHex(string(md5hash.Sum(nil)), 0)
	i := 0
	for size > 0 {
		ret = ret + base[i:i+1]
		i++
		if i >= len(base) {
			i = 0
		}
		size--
	}
	return ret

}

// 转换成unicode编码
func ToUnicode(s string) []byte {
	bs_UTF16LE, _, _ := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder(), []byte(s))
	return bs_UTF16LE
}

func UUIDv4() string {
	return uuid.New().String()
}

func RandomMD5Hash() string {
	md5hash := md5.New()
	md5hash.Write([]byte(time.Now().String()))
	return hex.EncodeToString(md5hash.Sum(nil))
}

// ExtractAllStringSubmatch提取所有正则匹配的字串
// content 代表原始字符串
// index 代表子字符串的索引
func ExtractAllStringSubmatch(reg *regexp.Regexp, content string, index int) (ret []string) {
	if m := reg.FindAllStringSubmatch(content, -1); len(m) > 0 {
		for _, v := range m {
			ret = append(ret, v[index])
		}
	}
	return ret
}
