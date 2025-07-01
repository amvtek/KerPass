package enroll

// EnrollReq is sent by the CardAgent client to the KerPass server.
// It is a plaintext that starts the EnrollProtocol.
type EnrollReq struct {
	RealmId  []byte `json:"1" cbor:"1,keyasint"`
	NoiseMsg []byte `json:"2" cbor:"2,keyasint"`
}

type EnrollCardCreateResp struct {
	RealmId []byte `json:"1" cbor:"1,keyasint"`
	CardId  []byte `json:"2" cbor:"2,keyasint"`
	AppName string `json:"3" cbor:"3,keyasint"`
	AppLogo []byte `json:"4" cbor:"4,keyasint"`
}
