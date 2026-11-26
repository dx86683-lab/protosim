package protocols

import (
	_ "embed"
	"encoding/xml"
	"strings"
)

// ONVIF WS-Discovery over UDP. Replies come from the configured JSON file,
// keyed by the local name of the first element in the SOAP body. Unknown
// methods get the reference's gSOAP-style fault.

//go:embed fixtures/onvif-default.json
var onvifDefault []byte

const onvifFault = `<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><SOAP-ENV:Body><SOAP-ENV:Fault><SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:Sender</SOAP-ENV:Value></SOAP-ENV:Code><SOAP-ENV:Reason><SOAP-ENV:Text>Method &apos;%s&apos; not implemented: method name or namespace not recognized</SOAP-ENV:Text></SOAP-ENV:Reason></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`

func init() {
	AddProtocol(NewProtocolInfo("onvif", serveONVIF, 3702),
		ProtocolParams{Name: "config_file", DefaultValue: "_onvif.json"})
}

// soapMethod returns the local name of the first child of the SOAP Body.
func soapMethod(request []byte) string {
	decoder := xml.NewDecoder(strings.NewReader(string(request)))
	inBody := false
	for i := 0; i < 1024; i++ {
		tok, err := decoder.Token()
		if err != nil {
			return ":"
		}
		if start, ok := tok.(xml.StartElement); ok {
			if inBody {
				return start.Name.Local
			}
			inBody = start.Name.Local == "Body"
		}
	}
	return ":"
}

func serveONVIF(conn *UDPConnection, request []byte) error {
	responses := map[string]string{}
	if err := loadResource("onvif", conn.GetStringParams("config_file", "_onvif.json"), &responses, onvifDefault); err != nil {
		return err
	}
	method := soapMethod(request)
	reply, ok := responses[method]
	if !ok {
		safeMethod := method
		if len(safeMethod) > 64 {
			safeMethod = safeMethod[:64]
		}
		var escaped strings.Builder
		_ = xml.EscapeText(&escaped, []byte(safeMethod))
		reply = strings.Replace(onvifFault, "%s", escaped.String(), 1)
	}
	_, err := conn.Write([]byte(reply))
	return err
}
