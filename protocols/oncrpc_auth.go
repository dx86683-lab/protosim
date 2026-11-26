package protocols

import "encoding/binary"

const (
	rpcAuthNone = 0
	rpcAuthSys  = 1
)

func rpcCallArguments(wire []byte) ([]byte, uint32) {
	credentialType, credential, ok := rpcOpaqueAuth(&wire)
	if !ok {
		return nil, 1 // AUTH_BADCRED
	}
	switch credentialType {
	case rpcAuthNone:
		if len(credential) != 0 {
			return nil, 1
		}
	case rpcAuthSys:
		if !validRPCAuthSys(credential) {
			return nil, 1
		}
	default:
		return nil, 5 // AUTH_TOOWEAK
	}
	verifierType, verifier, ok := rpcOpaqueAuth(&wire)
	if !ok || verifierType != rpcAuthNone || len(verifier) != 0 {
		return nil, 3 // AUTH_BADVERF
	}
	return wire, 0
}

func rpcOpaqueAuth(wire *[]byte) (uint32, []byte, bool) {
	if len(*wire) < 8 || binary.BigEndian.Uint32((*wire)[4:]) > 400 {
		return 0, nil, false
	}
	flavor := binary.BigEndian.Uint32(*wire)
	*wire = (*wire)[4:]
	body, ok := takeNFSOpaque(wire)
	return flavor, body, ok
}

func validRPCAuthSys(credential []byte) bool {
	if len(credential) < 4 {
		return false
	}
	credential = credential[4:] // timestamp
	host, ok := takeNFSOpaque(&credential)
	if !ok || len(host) > 255 || len(credential) < 12 {
		return false
	}
	groups := binary.BigEndian.Uint32(credential[8:])
	return groups <= 16 && len(credential) == 12+4*int(groups)
}
