package enroll

// EnrollReq is sent by the CardAgent client to the KerPass server.
// It is a plaintext that starts the EnrollProtocol.
type EnrollReq struct {
	RealmId []byte `json:"realm_id" cbor:"1,keyasint"` // Determine the Static Key used by the Server
	Msg     []byte `json:"noise_msg" cbor:"2,keyasint"`
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
	AuthorizationId []byte `json:"authorization_id" cbor:"1,keyasint"`
	PSKShare        []byte `json:"client_psk_share" cbor:"2,keyasint"`
}

func (self EnrollAuthorization) Check() error {
	asz := len(self.AuthorizationId)
	if asz < 32 {
		return newError("invalid AuthorizationId size, %d < 32", asz)
	}
	psz := len(self.PSKShare)
	if psz < 32 {
		return newError("invalid PSKShare size, %d < 32", psz)
	}

	return nil
}

// EnrollCardCreateResp is sent by the KerPass server to the CardAgent client.
// It contains information that are necessary for creating the Card.
type EnrollCardCreateResp struct {
	CardId   []byte `json:"card_id" cbor:"1,keyasint"`
	PSKShare []byte `json:"psk_share" cbor:"2,keyasint"`
	AppName  string `json:"app_name" cbor:"3,keyasint"`
	AppLogo  []byte `json:"app_logo" cbor:"4,keyasint"`
}

func (self EnrollCardCreateResp) Check() error {
	csz := len(self.CardId)
	if csz < 32 {
		return newError("Invalid CardId size, %d < 32", csz)
	}
	psz := len(self.PSKShare)
	if psz < 32 {
		return newError("invalid ServerPSKShare size, %d < 32", psz)
	}

	return nil
}
