package enroll

import (
	"code.kerpass.org/golang/pkg/credentials"
)

// EnrollReq is sent by the CardAgent client to the KerPass server.
// It is a plaintext that starts the EnrollProtocol.
type EnrollReq struct {
	RealmId credentials.RealmId `json:"rid" cbor:"1,keyasint"` // Determine the Static Key used by the Server
	Msg     []byte              `json:"msg" cbor:"2,keyasint"`
}

func (self *EnrollReq) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil EnrollReq")
	}
	if err := self.RealmId.Check(); nil != err {
		return wrapError(err, "failed RealmId validation")
	}
	msz := len(self.Msg)
	if msz < 32 {
		return wrapError(ErrValidation, "invalid Noise Msg size, %d < 32", msz)
	}

	return nil
}

// EnrollAuthorization is sent by the CardAgent client to the KerPass server.
type EnrollAuthorization struct {
	EnrollToken credentials.EnrollToken `json:"etk" cbor:"1,keyasint"`
}

func (self *EnrollAuthorization) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil EnrollAuthorization")
	}
	if err := self.EnrollToken.Check(); nil != err {
		return wrapError(err, "failed EnrollToken validation")
	}

	return nil
}

// EnrollCardCreateResp is sent by the KerPass server to the CardAgent client.
// It contains information that are necessary for creating the Card.
type EnrollCardCreateResp struct {
	IdToken credentials.IdToken `json:"idt" cbor:"1,keyasint"`
	UserId  string              `json:"user_id,omitempty" cbor:"2,keyasint,omitempty"`
	AppName string              `json:"app_name" cbor:"3,keyasint"`
	AppDesc string              `json:"app_desc,omitempty" cbor:"4,keyasint,omitempty"`
	AppLogo []byte              `json:"app_logo,omitempty" cbor:"5,keyasint,omitempty"`
}

func (self *EnrollCardCreateResp) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil EnrollCardCreateResp")
	}
	if err := self.IdToken.Check(); nil != err {
		return wrapError(err, "failed IdToken validation")
	}

	return nil
}
