package goutils

import (
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

func TestGetSysInfo(t *testing.T) {
	info := GetSysInfo(true)
	time.Now()
	log.Println(info.String(), info.UpTimeString())

	assert.True(t, len(info.Hostname) > 0)
}
