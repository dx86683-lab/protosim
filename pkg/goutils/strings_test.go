package goutils

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToHex(t *testing.T) {
	assert.Equal(t, "414141", ToHex("AAA", 0))
	assert.Equal(t, "0x414141", ToHex("AAA", 1))
	assert.Equal(t, `\x41\x41\x41`, ToHex("AAA", 2))
	assert.Equal(t, `41 41 41`, ToHex("AAA", 3))
}

func TestShellDoubleQuoteEscape(t *testing.T) {
	assert.Equal(t, `\\x74\\x65\\x73\\x74`, ShellDoubleQuoteEscape(`\x74\x65\x73\x74`))
	assert.Equal(t, `\"a\"`, ShellDoubleQuoteEscape(`"a"`))
}

func TestRandomHexString(t *testing.T) {
	//log.Println(RandomHexString(100))
	assert.Equal(t, 10, len(RandomHexString(10)))
	assert.Equal(t, 20, len(RandomHexString(20)))
	assert.NotEqual(t, RandomHexString(20), RandomHexString(20))
}

func TestToUnicode(t *testing.T) {
	assert.Equal(t, 2, len(ToUnicode("a")))
	assert.Equal(t, "UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAIgBEADoAXAB0AG0AZQBzAFwAVABNAEUAUwAtAE0ATwBVAEQATABFAFwAYQBwAGEAYwBoAGUALQBhAGMAdABpAHYAZQBtAHEALQA1AC4AMQA1AC4AOQBcAGIAaQBuAFwAdwBpAG4ANgA0AFwAdwBlAGIAYQBwAHAAcwBcAGEAZABtAGkAbgBcAHQAZQBzAHQAXAAyAGIAYwAwAGYAMgBiADUALgB0AHgAdAAiACAALQBWAGEAbAB1AGUAIAAiAHQAZQBzAHQAIgA=", base64.StdEncoding.EncodeToString(ToUnicode(`Set-Content -Path "D:\tmes\TMES-MOUDLE\apache-activemq-5.15.9\bin\win64\webapps\admin\test\2bc0f2b5.txt" -Value "test"`)))
	assert.Equal(t, 1, len([]byte("a")))
}

func TestGetStringInBetween(t *testing.T) {
	assert.Equal(t, "61189", GetStringInBetween("https://www.securityfocus.com/bid/61189", "www.securityfocus.com/bid/", ""))
	assert.Equal(t, "abc", GetStringInBetween("123abc456", "123", "456"))
	assert.Equal(t, "123", GetStringInBetween("123abc456", "", "abc"))
}
