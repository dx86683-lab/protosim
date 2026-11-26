package goutils

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

/*
--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw
Content-Disposition: form-data; name="input_localfile"; filename="2182075394.jsp"
Content-Type: image/jpeg

abc
--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw
Content-Disposition: form-data; name="uploadpath"

../webapps/notifymsg/devreport/
--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw--
*/
func TestGenMultipartFormData(t *testing.T) {
	body, boundary := GenMultipartFormData("tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw", []interface{}{
		map[string]string{
			"Name":        "input_localfile",
			"Value":       "abc",
			"ContentType": "image/jpeg",
			"FileName":    "1.txt",
		},
		map[string]string{
			"Name":  "uploadpath",
			"Value": "../webapps/notifymsg/devreport/",
		},
	})
	assert.Equal(t, `--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw
Content-Disposition: form-data; name="input_localfile"; filename="1.txt"
Content-Type: image/jpeg

abc
--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw
Content-Disposition: form-data; name="uploadpath"

../webapps/notifymsg/devreport/
--tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw--
`, strings.ReplaceAll(body, "\r", ""))
	assert.Equal(t, "tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw", boundary)
}
