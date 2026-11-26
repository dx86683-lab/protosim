package protocols

import (
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestMelsecqDiscover(t *testing.T) {
	go StartMelsecqDiscoverServer()

	time.Sleep(1 * time.Second)
	// 启动 调用nmap 进行扫描

	// 定义 nmap 命令和参数
	cmd := exec.Command("nmap", "--script", "melsecq-discover", "-sT", "-p", "5007", "127.0.0.1")

	// 执行命令并捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("【Unit Test】Error executing command: 请检查是否存在melsecq-discover.nse文件，", err)
		fmt.Println("【Unit Test】下载地址：https://github.com/w3h/icsmaster/blob/b98a41be7da4626daef32265cd5722f05f056d51/nse/melsecq-discover.nse#L17")
		return
	}

	// 打印命令输出
	fmt.Println(string(output))
}

func StartMelsecqDiscoverServer() {
	conn, _ := net.Listen("tcp", "127.0.0.1:5007")
	defer func(conn net.Listener) {
		err := conn.Close()
		if err != nil {
			logrus.Fatalln("server close err:", err)
		}
	}(conn)
	for {
		c, err := conn.Accept()
		if err != nil {
			logrus.Errorln("fake_winbox:server:ListenAndServe err:", err)
			continue
		}
		go handleMelsecqConnection(c, "TEST_PROTOCOL", discardMelsecqEvent)
	}
}
