package protocols

import (
	"log"
	"sort"
	"sync"
)

type Registor struct {
	sync.Map
}

var (
	registor Registor
)

// ProtocolInfo 对应协议的基础信息
type ProtocolInfo struct {
	Name            string                      `json:"name"` // 协议名称
	DefaultPort     uint16                      `json:"port"` //默认端口
	HandleFunc      interface{}                 `json:"-"`    //对应的处理函数
	DatagramHandler func(*BindInfo) UDPFunction `json:"-"`
	Params          []ProtocolParams            `json:"params,omitempty"`
}

// ProtocolParams 对应协议的单项参数配置
type ProtocolParams struct {
	Name         string      `json:"name"`           // 参数名称
	Type         string      `json:"type,omitempty"` // 类型
	DefaultValue interface{} `json:"default_value"`  // 默认值
}

func NewProtocolInfo(name string, f interface{}, defaultPort uint16) *ProtocolInfo {
	return &ProtocolInfo{
		Name:        name,
		DefaultPort: defaultPort,
		HandleFunc:  f,
	}
}

func AddProtocol(pi *ProtocolInfo, acceptParams ...ProtocolParams) {
	var aps []ProtocolParams
	for i := range acceptParams {
		aps = append(aps, acceptParams[i])
	}
	pi.Params = aps

	if _, loaded := registor.LoadOrStore(pi.Name, pi); loaded {
		log.Println("[Warning] protocol of", pi.Name, "already exists")
	}
}

func LookupProtocol(name string) (*ProtocolInfo, bool) {
	f, ok := registor.Load(name)
	if !ok {
		return nil, false
	}
	return f.(*ProtocolInfo), true
}

func GetProtocol(name string) *ProtocolInfo { // 加载协议名对应的配置参数
	f, ok := registor.Load(name)
	if !ok {
		panic("[ERROR] Unknown protocol name of " + name)
	}
	return f.(*ProtocolInfo)
}

func GetProtocolParamNames(name string) []string {
	pi := GetProtocol(name)
	names := make([]string, len(pi.Params))
	for i, para := range pi.Params {
		names[i] = para.Name
	}
	return names
}

func AllSupportProtocols() []string {
	var p []string
	registor.Range(func(key, value interface{}) bool {
		p = append(p, key.(string))
		return true
	})
	sort.Strings(p)
	return p
}

func ProtocolDetails() []*ProtocolInfo {
	var p []*ProtocolInfo
	registor.Range(func(key, value interface{}) bool {
		p = append(p, value.(*ProtocolInfo))
		return true
	})
	sort.Slice(p, func(i, j int) bool {
		if p[i].DefaultPort < p[j].DefaultPort {
			return true
		} else if p[i].DefaultPort > p[j].DefaultPort {
			return false
		}
		return p[i].Name < p[j].Name
	})
	return p
}
