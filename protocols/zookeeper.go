package protocols

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("zookeeper", ZooKeeper, 2181),
		ProtocolParams{
			Name:         "version",
			DefaultValue: "3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, built on 2024-02-12 22:16 UTC",
		},
	)
}

// ZooKeeper implements ZooKeeper four-letter word commands (ruok, stat, envi, conf, mntr, srvr).
func ZooKeeper(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	ver := sc.GetStringParams("version", "3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, built on 2024-02-12 22:16 UTC")

	buf := make([]byte, 256)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	cmd := strings.TrimSpace(string(buf[:n]))
	if len(cmd) > 4 {
		cmd = cmd[:4]
	}

	sc.LogWithRemote("zookeeper_cmd", sc.Conn.RemoteAddr(), logrus.Fields{
		"command": cmd,
	})

	var resp string
	switch cmd {
	case "ruok":
		resp = "imok"
	case "stat", "srvr":
		resp = fmt.Sprintf(
			"Zookeeper version: %s\nLatency min/avg/max: 0/0/1\nReceived: 42\nSent: 42\nConnections: 1\nOutstanding: 0\nZxid: 0x100000012\nMode: standalone\nNode count: 15\n",
			ver,
		)
	case "envi":
		resp = fmt.Sprintf(
			"Environment:\nzookeeper.version=%s\nhost.name=zk-node-01\njava.version=17.0.10\nos.name=Linux\nos.arch=amd64\n",
			ver,
		)
	case "conf":
		resp = "clientPort=2181\ndataDir=/var/lib/zookeeper/version-2\ntickTime=2000\nmaxClientCnxns=60\nminSessionTimeout=4000\nmaxSessionTimeout=40000\nserverId=0\n"
	case "mntr":
		resp = fmt.Sprintf("zk_version\t%s\nzk_server_state\tstandalone\nzk_znode_count\t15\nzk_watch_count\t0\nzk_open_file_descriptor_count\t48\n", ver)
	case "isro":
		resp = "rw"
	default:
		resp = fmt.Sprintf("%s is not executed because it is not in the whitelist.\n", cmd)
	}

	_, err = sc.Conn.Write([]byte(resp))
	return err
}
