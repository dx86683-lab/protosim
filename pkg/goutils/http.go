package goutils

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"
)

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

/*
Content-Type: multipart/form-data; boundary=tv9hbZwn8_fuiZmPCsawKlDoUkkVFB9r5uxWOarwGMRf2oHJfBwmFw

返回post body 和 boundary

params 每一个：
Name, Value, ContentType, FileName
*/
func GenMultipartFormData(boundary string, params []interface{}) (string, string) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	if len(boundary) > 0 {
		writer.SetBoundary(boundary)
	}

	for _, p := range params {
		param := p.(map[string]string)
		h := make(textproto.MIMEHeader)
		if filename, ok := param["FileName"]; ok {
			h.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
					escapeQuotes(param["Name"]), escapeQuotes(filename)))
			h.Set("Content-Type", "application/octet-stream")
		} else {
			h.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(param["Name"])))
		}
		if ctype, ok := param["ContentType"]; ok {
			h.Set("Content-Type", ctype)
		}

		part, _ := writer.CreatePart(h)
		part.Write([]byte(param["Value"]))
	}
	err := writer.Close()
	if err != nil {
		return "", ""
	}
	return body.String(), writer.Boundary()
}
