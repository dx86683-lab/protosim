package protocols

import (
	"crypto/subtle"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/dx86683-lab/protosim/pkg/ssl"
	"github.com/go-viper/mapstructure/v2"
	"github.com/sirupsen/logrus"
)

type BindInfo struct {
	Handler       string                                          `json:"handler,omitempty"`
	Port          uint16                                          `json:"port"`
	App           string                                          `json:"app,omitempty"`
	Params        map[string]interface{}                          `json:"params,omitempty"`
	IP            string                                          `json:"-"`
	Log           *logrus.Logger                                  `json:"-"`
	ActivityFn    func(addr net.Addr, bi *BindInfo, isClose bool) `json:"-"`
	buildHostinfo string                                          `json:"-"`
}

type HostInfo struct {
	IP       string     `json:"ip"`
	Handlers []BindInfo `json:"handlers,omitempty"`
	Template string     `json:"template,omitempty"` // 主机模版
}

func (ci *BindInfo) GetHostInfo() string {
	return fmt.Sprintf("%s:%d", ci.IP, ci.Port)
}

// 获取参数，如果没有key,返回nil
func (ci *BindInfo) GetParam(key string) interface{} {
	if v, ok := ci.Params[key]; ok {
		return v
	}
	return nil
}

func (ci *BindInfo) GetBoolParams(key string) bool {
	if v, ok := ci.Params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (ci *BindInfo) GenCert() ssl.CertGenerator {
	var certConf CertConfInfo
	info := ci.GetParam("cert")
	if info != nil {
		err := mapstructure.Decode(info, &certConf)
		if err != nil {
			logrus.Errorf("[%s] parse ssl cert info error: %s, use default cert.", ci.Handler, err)
			return DefaultCertInfo
		}
		return &certConf
	} else {
		return DefaultCertInfo
	}
}

func (ci *BindInfo) GetStringParams(key string, defaultValue string) string {
	if v, ok := ci.Params[key]; ok {
		if s, ok := v.(string); ok && len(s) > 0 {
			return s
		}
	}
	return defaultValue
}

func (ci *BindInfo) GetCertName() string {
	certName := ci.GetStringParams("cert_name", "")
	if certName == "" {
		certName = fmt.Sprintf("%s_%d", ci.IP, ci.Port)
	}
	return certName
}

func (ci *BindInfo) GetIntParams(key string, defaultValue int) int {
	if v, ok := ci.Params[key]; ok {
		switch t := v.(type) {
		case int:
			return t
		case float64:
			return int(t)
		default:
			panic(fmt.Sprintf("unsupport int params: %v type:%v", v, reflect.TypeOf(t)))
		}
	} else {
		return defaultValue
	}
}

// IsAccountValid 检查accouts配置项
// 第一个是是否验证成功，第二个是是否存在账号配置
func (ci *BindInfo) IsAccountValid(user, pass string) (bool, bool) {
	if accounts := ci.GetStringsParams("accounts", nil); len(accounts) > 0 {
		for _, up := range accounts {
			cfgUser, cfgPass, ok := strings.Cut(up, ":")
			if !ok {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(user), []byte(cfgUser)) == 1 &&
				subtle.ConstantTimeCompare([]byte(pass), []byte(cfgPass)) == 1 {
				return true, true
			}
		}
		return false, true
	}

	return true, false
}

func (ci *BindInfo) GetStringsParams(key string, defaultV []string) []string {
	var v []string
	if value, ok := ci.Params[key]; ok {
		switch items := value.(type) {
		case []interface{}:
			for _, up := range items {
				if s, ok := up.(string); ok {
					v = append(v, s)
				}
			}
		case []string:
			v = append(v, items...)
		}
	} else {
		v = defaultV
	}
	return v
}

// 新的连接活动
func (bi *BindInfo) AddActivity(addr net.Addr, isClose bool) {
	if bi.ActivityFn != nil {
		if addr != nil {
			bi.ActivityFn(addr, bi, isClose)
		}
	} else {
		//log.println("[WARNING] no ActivityFn of", bi.Handler)
	}
}
