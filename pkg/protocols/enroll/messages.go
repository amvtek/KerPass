package enroll

// EnrollReq is sent by the CardAgent client to the KerPass server.
// It is a plaintext that starts the EnrollProtocol.
type EnrollReq struct {
	RealmId []byte `json:"rid" cbor:"1,keyasint"` // Determine the Static Key used by the Server
	Msg     []byte `json:"msg" cbor:"2,keyasint"`
}

func (self EnrollReq) Check() error {
	rsz := len(self.RealmId)
	if rsz < 32 || rsz > 64 {
		return newError("invalid RealmId size, %d not in 32..64 range", rsz)
	}
	msz := len(self.Msg)
	if msz < 32 {
		return newError("invalid Noise Msg size, %d < 32", msz)
	}

	return nil
}

// EnrollAuthorization is sent by the CardAgent client to the KerPass server.
type EnrollAuthorization struct {
	AuthorizationId []byte `json:"aid" cbor:"1,keyasint"`
}

func (self EnrollAuthorization) Check() error {
	asz := len(self.AuthorizationId)
	if asz < 32 {
		return newError("invalid AuthorizationId size, %d < 32", asz)
	}

	return nil
}

// EnrollCardCreateResp is sent by the KerPass server to the CardAgent client.
// It contains information that are necessary for creating the Card.
type EnrollCardCreateResp struct {
	IdToken []byte `json:"idt" cbor:"1,keyasint"`
	UserId  string `json:"user_id,omitempty" cbor:"2,keyasint,omitempty"`
	AppName string `json:"app_name" cbor:"3,keyasint"`
	AppDesc string `json:"app_desc,omitempty" cbor:"4,keyasint,omitempty"`
	AppLogo []byte `json:"app_logo,omitempty" cbor:"5,keyasint,omitempty"`
}

func (self EnrollCardCreateResp) Check() error {
	csz := len(self.IdToken)
	if csz < 32 {
		return newError("Invalid IdToken size, %d < 32", csz)
	}

	return nil
}
