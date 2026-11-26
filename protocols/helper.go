package protocols

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/log"
)

func extractResource(protocol string, data []byte, filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		log.Debugf("[%s] extract resource to file %s.", protocol, filePath)
		dir := filepath.Dir(filePath)
		os.MkdirAll(dir, os.ModePerm)
		return ioutil.WriteFile(filePath, data, os.ModePerm)
	}
	return nil
}

func loadResource(protocol string, path string, data interface{}, defaultVal []byte) error {
	extractResource(protocol, defaultVal, path)

	d, err := os.ReadFile(path)
	if err != nil {
		logrus.Errorf("[%s] error read config file %s: %s", protocol, path, err)
		return err
	}
	err = json.Unmarshal(d, data)
	if err != nil {
		logrus.Errorf("[%s] error decode config file %s: %s", protocol, path, err)
		return err
	}
	return nil
}

func HasContentType(r *http.Request, mimetype string) bool {
	contentType := r.Header.Get("Content-type")
	if contentType == "" {
		return mimetype == "application/octet-stream"
	}

	for _, v := range strings.Split(contentType, ",") {
		t, _, err := mime.ParseMediaType(v)
		if err != nil {
			break
		}
		if t == mimetype {
			return true
		}
	}
	return false
}

func matchesConfiguredAccount(accounts []string, user, pass string) bool {
	for _, account := range accounts {
		name, password, ok := strings.Cut(account, ":")
		if ok && name == user && password == pass {
			return true
		}
	}
	return false
}

// loadResponseFixture reads only the configured local file. The embedded
// response set serves deployments with no separate default fixture.
func loadResponseFixture(path, defaultPath string, builtIn []byte, destination any) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && path == defaultPath {
		return json.Unmarshal(builtIn, destination)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("fixture requires a regular file of at most 1 MiB")
	}
	return json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(destination)
}
