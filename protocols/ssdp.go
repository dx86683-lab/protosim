package protocols

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var SSDP_SERVER_VERSION = "OS 1.0 UPnP/1.0 Realtek/V1.3"
var SSDP_DEV_TYPE = "upnp:rootdevice"
var SSDP_DEV_USN = "uuid:00000000-0000-0000-0000-000000000000::upnp:rootdevice"
var SSDP_MAX_AGE = 1800
var SSDP_LOCATION = "http://192.168.0.1:54383/rootDesc.xml"
var SSDP_DEFAULT_HEADER = []string{}

const SSDPMulticastAddress = "239.255.255.250"
const SSDPPort = 1900

func init() {
	AddProtocol(NewProtocolInfo("ssdp", SSDP, SSDPPort), ProtocolParams{
		Name:         "server_version",
		DefaultValue: SSDP_SERVER_VERSION,
	}, ProtocolParams{
		Name:         "max_age",
		DefaultValue: SSDP_MAX_AGE,
	}, ProtocolParams{
		Name:         "dev_type",
		DefaultValue: SSDP_DEV_TYPE,
	}, ProtocolParams{
		Name:         "dev_location",
		DefaultValue: SSDP_LOCATION,
	}, ProtocolParams{
		Name:         "dev_usn",
		DefaultValue: SSDP_DEV_USN,
	}, ProtocolParams{
		Name:         "headers",
		DefaultValue: SSDP_DEFAULT_HEADER,
	})
}

func createSsdpHeader(head string, vars [][]string, isResponse bool) []byte {
	buf := bytes.Buffer{}
	if isResponse {
		buf.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", head))
	} else {
		buf.WriteString(fmt.Sprintf("%s * HTTP/1.1\r\n", head))
	}
	for _, v := range vars {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", v[0], v[1]))
	}
	buf.WriteString("\r\n")
	return []byte(buf.String())
}

func extractUrnDeviceIdFromUsn(usn string) (deviceId, urn string) {
	if len(usn) > 0 {
		parts := strings.Split(usn, ":")
		if len(parts) > 2 {
			if parts[0] == "uuid" {
				deviceId = parts[1]
				urn = strings.TrimPrefix(usn, "uuid:"+deviceId+":")
				if parts[2] == "" {
					urn = strings.TrimPrefix(urn, ":")
				}
			} else {
				urn = usn
			}
		}
	}
	return
}

func parseHeaders(hdrs []string) [][]string {
	res := make([][]string, 0)
	for _, hdr := range hdrs {
		line := strings.SplitN(hdr, ": ", 2)
		if len(line) > 1 {
			res = append(res, line)
		}
	}
	return res
}

func ssdpTypedTarget(target string) (string, uint64) {
	parts := strings.Split(target, ":")
	if len(parts) != 5 || parts[0] != "urn" || parts[1] == "" ||
		(parts[2] != "device" && parts[2] != "service") || parts[3] == "" {
		return "", 0
	}
	version, err := strconv.ParseUint(parts[4], 10, 32)
	if err != nil || version == 0 {
		return "", 0
	}
	return target[:strings.LastIndexByte(target, ':')], version
}

func ssdpSearchResponse(target, deviceType, usn string) (string, string) {
	if target == "ssdp:all" || target == deviceType {
		return deviceType, usn
	}
	id, suffix, _ := strings.Cut(usn, "::")
	if !strings.HasPrefix(id, "uuid:") || len(id) == len("uuid:") {
		return "", ""
	}
	if target == id {
		return id, id
	}
	requestedType, requestedVersion := ssdpTypedTarget(target)
	configuredType, configuredVersion := ssdpTypedTarget(deviceType)
	if suffix == deviceType && requestedType != "" && requestedType == configuredType && requestedVersion <= configuredVersion {
		return target, id + "::" + target
	}
	return "", ""
}

func SSDP(uc *UDPConnection, b []byte) error {
	return serveSSDP(uc, b, false)
}

func SSDPMulticast(uc *UDPConnection, payload []byte) error {
	return serveSSDP(uc, payload, true)
}

func serveSSDP(uc *UDPConnection, b []byte, multicast bool) error {
	defer func() {
		// logrus.Infof("SSDP handler exit.")
		if err := recover(); err != nil {
			logrus.Errorf("SSDP handler proc panic. error:%v, stack:\n%s\n", err, string(debug.Stack()))
		}
	}()

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		logrus.Warnf("[SSDP] Error reading request: %s", err)
		return err
	}

	if req.URL.Path != "*" {
		logrus.Warnf("[SSDP] Unknown path requested: %s", req.URL.Path)
		return errors.New("[SSDP] unknown path")
	}

	server := uc.GetStringParams("server_version", SSDP_SERVER_VERSION)
	max_age := uc.GetIntParams("max_age", SSDP_MAX_AGE)
	dev_type := uc.GetStringParams("dev_type", SSDP_DEV_TYPE)
	dev_usn := uc.GetStringParams("dev_usn", SSDP_DEV_USN)
	location := uc.GetStringParams("dev_location", SSDP_LOCATION)

	uc.LogInfo("request", map[string]interface{}{"method": req.Method})
	if req.Method == "M-SEARCH" {
		man, targets := req.Header.Values("MAN"), req.Header.Values("ST")
		if req.Proto != "HTTP/1.1" || req.Host == "" || len(man) != 1 || man[0] != `"ssdp:discover"` ||
			len(targets) != 1 || targets[0] == "" {
			return nil
		}
		st, usn := ssdpSearchResponse(targets[0], dev_type, dev_usn)
		if st == "" {
			return nil
		}
		if multicast {
			mx := req.Header.Values("MX")
			if req.Host != SSDPMulticastAddress+":1900" || len(mx) != 1 {
				return nil
			}
			seconds, err := strconv.ParseUint(mx[0], 10, 32)
			if err != nil || seconds == 0 {
				return nil
			}
			window := time.Duration(min(seconds, 5)) * time.Second
			time.Sleep(time.Duration(rand.Int64N(int64(window))))
		}
		headers := [][]string{
			{"CACHE-CONTROL", fmt.Sprintf("max-age=%d", max_age)},
			{"ST", st},
			{"USN", usn},
			{"EXT", ""},
			{"SERVER", server},
		}
		hdrs := parseHeaders(uc.GetStringsParams("headers", SSDP_DEFAULT_HEADER))
		headers = append(headers, hdrs...)
		headers = append(headers, []string{"LOCATION", location})
		msg := createSsdpHeader(
			"200 OK",
			headers,
			true,
		)
		_, err := uc.Write(msg)
		return err
	}

	return nil
}
