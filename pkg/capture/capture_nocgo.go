//go:build !cgo

package capture

import "github.com/sirupsen/logrus"

func LogUDP(devName string, log *logrus.Logger) {
	logrus.Warnf("[UDPLogger] disabled on non-cgo build (device=%s)", devName)
}

func LogICMP(devName string, log *logrus.Logger) {
	logrus.Warnf("[ICMPLogger] disabled on non-cgo build (device=%s)", devName)
}

func LogSYN(devName string, log *logrus.Logger) {
	logrus.Warnf("[SYNLogger] disabled on non-cgo build (device=%s)", devName)
}
