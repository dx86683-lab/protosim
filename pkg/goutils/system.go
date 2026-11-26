package goutils

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// 从文件列表中返回第一个存在的文件路径
func LoadFirstExistsFile(paths []string) string {
	for _, p := range paths {
		if FileExists(p) {
			return p
		}
	}
	return ""
}

// 从默认的一些目录中搜索文件
func LoadFileFromDefaultDir(filename string) string {
	paths := []string{
		filename,
		filepath.Join("external", filename),
		filepath.Join(GetCurrentProcessFileDir(), filename),
		filepath.Join(GetCurrentProcessFileDir(), "external", filename),
		filepath.Join(UserHomeDir(), filename),
		filepath.Join(UserHomeDir(), "Downloads", filename),
		filepath.Join(UserHomeDir(), "Download", filename),
	}
	f, _ := filepath.Abs(filepath.Join("..", "external", filename))
	paths = append(paths, f)
	f, _ = filepath.Abs(filepath.Join("..", "..", "external", filename))
	paths = append(paths, f)
	f, _ = filepath.Abs(filepath.Join("..", "..", "..", "external", filename))
	paths = append(paths, f)
	f, _ = filepath.Abs(filepath.Join("..", "..", "..", "protosim", "cmd", "protosim-cmd", "external", filename))
	paths = append(paths, f)
	return LoadFirstExistsFile(paths)
}

// 获得当前程序所在的目录
func GetCurrentProcessFileDir() string {
	return filepath.Dir(os.Args[0])
}

// 获得当前用户的主目录
func UserHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

// 在时间范围内执行系统命令，并且将输出返回（stdout和stderr）
func ExecCmdWithTimeout(timeout time.Duration, arg ...string) ([]byte, error) {
	defer func() {
		if x := recover(); x != nil {
			log.Println("[WARNING] ExecCmdWithTimeout failed:", x)
		}
	}()

	routeCmd := exec.Command(arg[0], arg[1:]...)

	var timer *time.Timer
	timer = time.AfterFunc(timeout, func() {
		timer.Stop()
		if routeCmd.Process != nil {
			routeCmd.Process.Kill()
		}
	})

	return routeCmd.CombinedOutput()
}
