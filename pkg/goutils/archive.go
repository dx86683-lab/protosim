package goutils

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// createExpArchive 函数从 srcFilepath 文件夹读取 exp 文件，然后打包写到
// 以当前时间戳命名的文件中。
func CreateExpArchive(srcFilepath string) {
	fileInfos, err := ioutil.ReadDir(srcFilepath)
	if err != nil {
		log.Fatal(err)
	}

	archiveFilename := time.Now().Format("20060102150405")
	log.Println(archiveFilename)
	fw, err := os.Create(archiveFilename + ".poc")
	if err != nil {
		log.Fatal(err)
	}
	defer fw.Close()
	tw := tar.NewWriter(fw)
	defer func() {
		if err := tw.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	for i, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			continue
		}
		if strings.ToLower(filepath.Ext(fileInfo.Name())) != ".json" &&
			strings.ToLower(filepath.Ext(fileInfo.Name())) != ".go" {
			continue
		}
		srcFilename := filepath.Join(srcFilepath, fileInfo.Name())
		log.Println(i, srcFilepath, fileInfo.Name(), srcFilename)

		hdr, err := tar.FileInfoHeader(fileInfo, "")
		if err != nil {
			log.Fatal(err)
		}
		err = tw.WriteHeader(hdr)
		if err != nil {
			log.Fatal(err)
		}
		fr, err := os.Open(srcFilename)
		if err != nil {
			log.Fatal(err)
		}
		defer fr.Close()
		written, err := io.Copy(tw, fr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Writen %d chars\n", written)
	}
}
