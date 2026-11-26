package goutils

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"time"
)

// 是否正确的IP格式
func IsValidIP(ip string) bool {
	if net.ParseIP(ip) != nil { // IP
		return true
	}
	return false
}

// interface 转换成整形
func B2I(data interface{}) int {
	if data == nil {
		return 0
	}

	//log.Printf("%T: %v", data)

	switch data.(type) {
	case float32:
		return int(data.(float32))
	case float64:
		return int(data.(float64))
	case int:
		return data.(int)
	case int32:
		return int(data.(int32))
	case int64:
		return int(data.(int64))
	case bool:
		if data.(bool) {
			return 1
		} else {
			return 0
		}
	case string:
		if data.(string) == "0" || strings.ToLower(data.(string)) == "false" {
			return 0
		} else {
			return 1
		}
	default:
		panic("unknown datatype")
	}
	return 0
}

// interface转换成字符串
func B2S(data interface{}) string {
	if data == nil {
		return ""
	}

	//log.Printf("%T: %v", data)

	switch data.(type) {
	case string:
		return data.(string)
	case []uint8:
		return string(data.([]byte))
	case int:
		return strconv.Itoa(data.(int))
	case int32:
		return strconv.Itoa(int(data.(int32)))
	case int64:
		return strconv.FormatInt(data.(int64), 10)
	case float32:
		return strconv.Itoa(int(data.(float32)))
	case float64:
		return strconv.FormatInt(int64(data.(float64)), 10)
	case time.Time:
		return data.(time.Time).Format("2006-01-02 15:04:05")
	default:
		panic("unknown datatype")
	}
	return ""
}

// 根据json获取path对应的value
// path 必须以/开头
func GetJSONValueByPath(data map[string]interface{}, path string) interface{} {
	if path[0] != '/' {
		panic("GetJSONValueByPath not start with /")
	}
	dotPaths := strings.Split(path, "/")
	for i := 0; i < len(dotPaths); i++ {
		if p := strings.Trim(dotPaths[i], " \t"); len(p) > 0 {
			if v, ok := data[p]; ok {
				if data, ok = v.(map[string]interface{}); !ok {
					// 到子节点了
					return v
				}
			} else {
				return nil
			}
		}
	}
	return data
}

// java运行cmd的过程中，不允许>管道，可以通过bash的base64方法进行
func BashBase64CMD(cmd string) string {
	cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	return `bash -c {echo,` + cmdBase64 + `}|{base64,-d}|{bash,-i}`
}
