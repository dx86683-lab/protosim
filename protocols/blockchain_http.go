package protocols

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

//go:embed fixtures/eos-default.json
var eosDefault []byte

//go:embed fixtures/ethereum-default.json
var ethereumDefault []byte

const (
	eosConfig         = "eos.json"
	eosServer         = "WebSocket++/0.7.0"
	ethereumConfig    = "ethereum.json"
	ethereumVersion   = "Geth/v1.9.18-stable-f5382591/linux-amd64/go1.14.6"
	blockchainMaxBody = 1 << 20
)

func init() {
	AddProtocol(NewProtocolInfo("eos", serveEOS, 8888),
		ProtocolParams{Name: "server_version", DefaultValue: eosServer},
		ProtocolParams{Name: "config_file", DefaultValue: eosConfig})
	AddProtocol(NewProtocolInfo("ethereum", serveEthereum, 8545),
		ProtocolParams{Name: "server_version", DefaultValue: ""},
		ProtocolParams{Name: "ethereum_version", DefaultValue: ethereumVersion},
		ProtocolParams{Name: "config_file", DefaultValue: ethereumConfig})
}

func blockchainResponses(ci *ConfigInfo, name, path string, defaults []byte) (map[string]any, error) {
	var raw map[string]json.RawMessage
	if err := loadResponseFixture(ci.GetStringParams("config_file", path), path, defaults, &raw); err != nil {
		if ci.Log != nil {
			ci.Log.WithError(err).WithField("handler", name).Error("load response configuration")
		}
		return nil, err
	}
	values := make(map[string]any, len(raw))
	for key, value := range raw {
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		var result any
		if err := decoder.Decode(&result); err != nil {
			return nil, err
		}
		values[key] = result
	}
	return values, nil
}

func blockchainHTTP(ci *ConfigInfo, server string, reply func(*http.Request, []byte) any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := io.ReadAll(http.MaxBytesReader(w, r.Body, blockchainMaxBody))
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		remote, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		logSessionEvent(ci, remote, "request", logrus.Fields{
			"method": r.Method, "uri": r.RequestURI, "headers": r.Header, "body": string(request),
		})
		w.Header().Set("Server", server)
		value := reply(r, request)
		if value == nil {
			w.Header().Set("Content-Length", "0")
			return
		}
		body, err := json.Marshal(value)
		if err != nil {
			http.Error(w, "invalid response configuration", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	})
}

func unavailableBlockchainHTTP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid response configuration", http.StatusInternalServerError)
	})
}

func serveEOS(ci *ConfigInfo) http.Handler {
	responses, err := blockchainResponses(ci, "eos", eosConfig, eosDefault)
	if err != nil {
		return unavailableBlockchainHTTP()
	}
	return blockchainHTTP(ci, ci.GetStringParams("server_version", eosServer), func(r *http.Request, _ []byte) any {
		if response, ok := responses[r.URL.Path]; ok {
			return response
		}
		return responses["error"]
	})
}

func serveEthereum(ci *ConfigInfo) http.Handler {
	responses, err := blockchainResponses(ci, "ethereum", ethereumConfig, ethereumDefault)
	if err != nil {
		return unavailableBlockchainHTTP()
	}
	responses["web3_clientVersion"] = ci.GetStringParams("ethereum_version", ethereumVersion)
	return blockchainHTTP(ci, ci.GetStringParams("server_version", "Apache"), func(r *http.Request, body []byte) any {
		if r.Method != http.MethodPost {
			return nil
		}
		var request *struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		response := map[string]any{"jsonrpc": "2.0", "id": nil}
		if err := json.Unmarshal(body, &request); err != nil || request == nil {
			response["error"] = map[string]any{"code": -32700, "message": "parse error"}
			return response
		}
		if len(request.ID) > 0 {
			var idVal any
			if err := json.Unmarshal(request.ID, &idVal); err != nil {
				response["error"] = map[string]any{"code": -32700, "message": "parse error"}
				return response
			}
			switch idVal.(type) {
			case nil, string, float64:
				response["id"] = request.ID
			default:
				response["error"] = map[string]any{"code": -32700, "message": "parse error"}
				return response
			}
		}
		if result, found := responses[request.Method]; found {
			response["result"] = result
		} else {
			response["error"] = map[string]any{
				"code": -32601, "message": "the method " + request.Method + " does not exist/is not available",
			}
		}
		return response
	})
}
