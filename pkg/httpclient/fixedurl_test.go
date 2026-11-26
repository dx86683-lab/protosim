package httpclient

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewFixUrl(t *testing.T) {
	if NewFixUrl("aa 1.1.1.1-") != nil {
		t.Fatal("invalid url should return nil")
	}

	assert.Equal(t, "http://1.1.1.1", NewFixUrl("1.1.1.1:80").FixedHostInfo, "should be equal")
	assert.Equal(t, "http://1.1.1.1", NewFixUrl("http://1.1.1.1:80").FixedHostInfo, "should be equal")

	assert.Equal(t, "1.1.1.1:9200", NewFixUrl("1.1.1.1:9200").HostInfo, "should be equal")
	assert.Equal(t, "1.1.1.1", NewFixUrl("1.1.1.1:9200").IP, "should be equal")
	assert.Equal(t, "9200", NewFixUrl("1.1.1.1:9200").Port, "should be equal")
	assert.Equal(t, "9200", NewFixUrl("https://1.1.1.1:9200").Port, "should be equal")
	assert.Equal(t, "443", NewFixUrl("https://1.1.1.1").Port, "should be equal")
	assert.Equal(t, "80", NewFixUrl("http://1.1.1.1").Port, "should be equal")
	assert.Equal(t, "1.1.1.1:443", NewFixUrl("https://1.1.1.1").HostInfo, "should be equal")
	assert.Equal(t, "1.1.1.1", NewFixUrl("https://1.1.1.1").IP, "should be equal")
	assert.Equal(t, "https://1.1.1.1", NewFixUrl("https://1.1.1.1").FixedHostInfo, "should be equal")
	assert.Equal(t, "1.1.1.1:9200", NewFixUrl("https://1.1.1.1:9200").HostInfo, "should be equal")
	assert.Equal(t, "1.1.1.1:9200", NewFixUrl("http://1.1.1.1:9200").HostInfo, "should be equal")
	assert.Equal(t, "1.1.1.1", NewFixUrl("https://1.1.1.1:9200").IP, "should be equal")
	assert.Equal(t, "https://1.1.1.1:9200", NewFixUrl("https://1.1.1.1:9200").FixedHostInfo, "should be equal")

	// 域名（标准端口）
	assert.Equal(t, "example.com:443", NewFixUrl("https://example.com").HostInfo, "should be equal")
	assert.Equal(t, "example.com", NewFixUrl("https://example.com").IP, "should be equal")
	assert.Equal(t, "https://example.com", NewFixUrl("https://example.com").FixedHostInfo, "should be equal")
	// 域名（非标准端口）
	assert.Equal(t, "example.com:9200", NewFixUrl("http://example.com:9200").HostInfo, "should be equal")
	assert.Equal(t, "example.com", NewFixUrl("https://example.com:9200").IP, "should be equal")
	assert.Equal(t, "https://example.com:9200", NewFixUrl("https://example.com:9200").FixedHostInfo, "should be equal")

	assert.Equal(t, "/index.php?id=123", NewFixUrl("https://1.1.1.1/index.php?id=123").PathWithQuery(), "should be equal")
	//assert.Equal(t, "id=123", NewFixUrl("https://1.1.1.1/index.php?id=123").Query, "should be equal")

	assert.Equal(t, "ldap", NewFixUrl("ldap://docker.for.mac.localhost:11111/").Scheme())

	assert.Equal(t, "/a1/b2/", NewFixUrl("http://1.1.1.1/a1/b2/c.html").Dir, "should be equal")
	assert.Equal(t, "c.html", NewFixUrl("http://1.1.1.1/a1/b2/c.html").File, "should be equal")
	assert.Equal(t, ".html", NewFixUrl("http://1.1.1.1/a1/b2/c.html").Ext, "should be equal")
}

func TestNewFixIPV6Url(t *testing.T) {
	assert.Equal(t, "http://[2408:8270:9e12:dd00::1]:5351",
		NewFixUrl("[2408:8270:9e12:dd00::1]:5351").FixedHostInfo, "should be equal")

	assert.Equal(t, "2408:8270:9e12:dd00::1",
		NewFixUrl("http://[2408:8270:9e12:dd00::1]:5351/?ad=adfasfdsa").IP, "should be equal")

	assert.Equal(t, "5351",
		NewFixUrl("http://[2408:8270:9e12:dd00::1]:5351/?ad=adfasfdsa").Port, "should be equal")

	assert.Equal(t, "http://[2408:8270:9e12:dd00::1]",
		NewFixUrl("http://[2408:8270:9e12:dd00::1]:80/?ad=adfasfdsa").FixedHostInfo, "should be equal")

	assert.Equal(t, "https://[2408:8270:9e12:dd00::1]",
		NewFixUrl("https://[2408:8270:9e12:dd00::1]:443/?ad=adfasfdsa").FixedHostInfo, "should be equal")

	assert.Equal(t, "https://[2408:8270:9e12:dd00::1]:80",
		NewFixUrl("https://[2408:8270:9e12:dd00::1]:80/?ad=adfasfdsa").FixedHostInfo, "should be equal")

	assert.Equal(t, "http://[fe80::185d:dbf4:8e86:2cff%WLAN]",
		NewFixUrl("[fe80::185d:dbf4:8e86:2cff%25WLAN]").FixedHostInfo, "should be equal")

	assert.Equal(t, "fe80::185d:dbf4:8e86:2cff%WLAN",
		NewFixUrl("[fe80::185d:dbf4:8e86:2cff%25WLAN]").IP, "should be equal")
}
