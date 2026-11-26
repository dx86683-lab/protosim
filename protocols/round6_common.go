package protocols

import (
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

// logSessionEvent records a protocol event when a logger is configured.
func logSessionEvent(ci *ConfigInfo, remote net.Addr, msg string, fields logrus.Fields) {
	if ci == nil || ci.Log == nil || ci.BindInfo == nil {
		return
	}
	ci.LogWithRemote(msg, remote, fields)
}

// canonicalParamKey returns the configured value for key, accepting the
// lower-case spelling produced by Viper for nested configuration keys.
func canonicalParamKey[V any](values map[string]V, key string) (V, bool) {
	if v, ok := values[key]; ok {
		return v, true
	}
	v, ok := values[strings.ToLower(key)]
	return v, ok
}
