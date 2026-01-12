// Package airgap defines the KerPass "airgap" messages.
// Those messages (aka PDU) are exchanged in conversations between the CardAgent & CardApp over AirGap.
package airgap

import (
	"net/url"
	"slices"

	"github.com/fxamacker/cbor/v2"

	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
)

const (
	// Tag in range 0-23 have a 1 byte long CBOR encoding that is (192 + Tag value)
	// Tag in range 16-23 are preferred as they are not currently assigned
	TagAgentCardCreate    = 16
	TagAgentCardChallenge = 17
	TagAppOTK             = 16
)

// AgentMsg is implemented by all message types that may be sent by the CardAgent.
type AgentMsg interface {
	// AgentTag returns the CBOR tag value to use when marshaling to CBOR.
	AgentTag() uint64
}

// AgentCardCreate is sent by the CardAgent to the CardApp to initiate new Card creation
type AgentCardCreate struct {
	// Realm identifier (min 32 bytes)
	RealmId []byte `json:"rId" cbor:"1,keyasint"`

	// Authorization  ID (min 32 bytes)
	AuthorizationId []byte `json:"authId" cbor:"2,keyasint"`

	// Authentication server URL (max 128 chars)
	AuthServerUrl string `json:"asu" cbor:"3,keyasint"`
}

// AgentTag returns TagAgentCardCreate for CBOR marshaling.
func (self *AgentCardCreate) AgentTag() uint64 {
	return TagAgentCardCreate
}

// Check returns an error if the AgentCardCreate is invalid.
func (self *AgentCardCreate) Check() error {

	// check RealmId
	if len(self.RealmId) < 32 {
		return newError("invalid RealmId, len < 32")
	}

	// check AuthorizationId
	if len(self.AuthorizationId) < 32 {
		return newError("invalid AuthorizationId, len < 32")
	}

	// check AuthServerUrl
	if len(self.AuthServerUrl) > 128 {
		return newError("invalid AuthServerUrl, len > 128")
	}
	asu, err := url.Parse(self.AuthServerUrl)
	if nil != err {
		return wrapError(err, "invalid AuthServerUrl")
	}
	if !slices.Contains([]string{"http", "https"}, asu.Scheme) {
		return newError("invalid AuthServerUrl scheme")
	}

	return nil
}

// AgentCardChallenge requests OTP/OTK generation from CardApp for a specific Realm.
type AgentCardChallenge struct {
	// Realm of the Cards than can be used to generate the OTP/OTK
	RealmId []byte `json:"rId" cbor:"1,keyasint"`

	// Context hash calculated by the CardAgent based on Request acquired parameters such as session id, login page url, TLS certificate...
	Context []byte `json:"ctx" cbor:"2,keyasint"`

	// EPHEMSEC scheme in compressed form
	Scheme uint16 `json:"scheme" cbor:"3,keyasint"`

	// One time pad used to mask generated OTP
	// This pad prevent usage of keyboard entered OTP by a malicious App acting as the CardAgent...
	OtpPad []byte `json:"pad" cbor:"4,keyasint,omitempty"`

	// Server Ephemeral public key
	E credentials.PublicKeyHandle `json:"E" cbor:"5,keyasint"`

	// Server Static public key
	// Empty when Scheme KeyExchange pattern is E1S1
	S credentials.PublicKeyHandle `json:"S" cbor:"6,keyasint,omitzero"`

	// Server generated nonce
	INonce []byte `json:"nonce" cbor:"7,keyasint"`
}

// AgentTag returns TagAgentCardChallenge for CBOR marshaling.
func (self *AgentCardChallenge) AgentTag() uint64 {
	return TagAgentCardChallenge
}

// Check returns an error if the AgentCardChallenge is invalid.
func (self *AgentCardChallenge) Check() error {
	// check RealmId
	if len(self.RealmId) < 32 {
		return newError("Invalid RealmId, len < 32")
	}

	// check Scheme
	sch, err := ephemsec.GetScheme(self.Scheme)
	if nil != err {
		return wrapError(err, "failed Scheme lookup")
	}
	curve := sch.Curve().Curve

	// check OtpPad
	err = checkPad(self.OtpPad, sch.B(), sch.P())
	if nil != err {
		return wrapError(err, "failed pad validation")
	}

	// check the E, S public keys
	if self.E.IsZero() {
		return newError("missing E public key")
	}
	if self.E.Curve() != curve {
		return newError("invalid E not on Scheme curve")
	}
	switch sch.KeyExchangePattern() {
	case "E1S2", "E2S2":
		if self.S.IsZero() {
			return newError("missing S public key")
		}
		if self.S.Curve() != curve {
			return newError("invalid S not on Scheme curve")
		}
	}

	// check INonce
	if len(self.INonce) < 16 {
		return newError("invalid INonce, len < 16")
	}

	return nil
}

// MarshalAgentMsg validates and CBOR-marshals an AgentMsg with its proper CBOR tag.
func MarshalAgentMsg(msg AgentMsg) ([]byte, error) {
	var err error
	if v, checkable := msg.(checker); checkable {
		err = v.Check()
		if nil != err {
			return nil, wrapError(err, "failed msg Check")
		}
	}
	srzmsg, err := cbor.Marshal(cbor.Tag{Number: msg.AgentTag(), Content: msg})

	return srzmsg, wrapError(err, "failed cbor.Marshal")
}

// UnmarshalAgentMsg CBOR-unmarshals data into the correct AgentMsg type based on its CBOR tag.
// It errors if the resulting message is invalid.
func UnmarshalAgentMsg(srzmsg []byte) (AgentMsg, error) {
	tag := cbor.RawTag{}
	err := cbor.Unmarshal(srzmsg, &tag)
	if nil != err {
		return nil, wrapError(err, "failed reading msg tag")
	}

	var agentmsg AgentMsg
	switch tag.Number {
	case TagAgentCardCreate:
		msg := &AgentCardCreate{}
		err = wrapError(cbor.Unmarshal(tag.Content, msg), "failed cbor.Unmarshal")
		agentmsg = msg
	case TagAgentCardChallenge:
		msg := &AgentCardChallenge{}
		err = wrapError(cbor.Unmarshal(tag.Content, msg), "failed cbor.Unmarshal")
		agentmsg = msg
	default:
		err = newError("invalid AgentMsg tag")
	}
	if nil != err {
		return nil, err
	}
	if v, checkable := agentmsg.(checker); checkable {
		err = wrapError(v.Check(), "loaded an invalid msg")
	}

	return agentmsg, err
}

// checkPad validates that each byte in pad is in [0, base) interval.
// For base=256, pad is unused and always valid. For other bases, validates length and digit range.
func checkPad(pad []byte, base int, size int) error {
	switch base {
	case 256:
		// pad is not used if base is 256
		return nil
	case 10, 16, 32:
		if len(pad) != size {
			return newError("invalid pad size")
		}
	default:
		return newError("invalid base")
	}
	for _, digit := range pad {
		// each pad digit must be in [0..base) interval
		// this to allow alphabet encoding after xoring with otp...
		if int(digit) >= base {
			return newError("invalid pad, digit not in [0..base) interval")
		}
	}

	return nil
}

// AppMsg is implemented by all message types that may be sent by the CardApp.
type AppMsg interface {
	// AppTag returns the CBOR tag value to use when marshaling to CBOR.
	AppTag() uint64
}

// AppOTK is sent by CardApp to Agent in response to AgentCardChallenge.
type AppOTK struct {
	// CardId as registered with authentication server
	CardId []byte `json:"cId" cbor:"1,keyasint"`

	// CardApp generated OTK
	OTK []byte `json:"otk" cbor:"2,keyasint"`

	// CardApp Ephemeral public key
	// Used when Scheme KeyExchange pattern is E2S2
	E credentials.PublicKeyHandle `json:"E" cbor:"3,keyasint,omitzero"`
}

// AppTag returns TagAppOTK for CBOR marshaling.
func (self *AppOTK) AppTag() uint64 {
	return TagAppOTK
}

// Check returns an error if the AppOTK is invalid.
func (self *AppOTK) Check() error {
	if len(self.CardId) != 32 {
		return newError("invalid CardId, len < 32")
	}
	if len(self.OTK) < 4 {
		// see EPHEMSEC specs 5.4.3
		return newError("invalid OTK, len < 4")
	}

	return nil
}

// MarshalAppMsg validates and CBOR-marshals an AppMsg with its proper CBOR tag.
func MarshalAppMsg(msg AppMsg) ([]byte, error) {
	var err error
	if v, checkable := msg.(checker); checkable {
		err = v.Check()
		if nil != err {
			return nil, wrapError(err, "failed msg Check")
		}
	}
	srzmsg, err := cbor.Marshal(cbor.Tag{Number: msg.AppTag(), Content: msg})

	return srzmsg, wrapError(err, "failed cbor.Marshal")
}

// UnmarshalAppMsg CBOR-unmarshals data into the correct AppMsg type based on its CBOR tag.
// It errors if the resulting message is invalid.
func UnmarshalAppMsg(srzmsg []byte) (AppMsg, error) {
	tag := cbor.RawTag{}
	err := cbor.Unmarshal(srzmsg, &tag)
	if nil != err {
		return nil, wrapError(err, "failed reading msg tag")
	}

	var appmsg AppMsg
	switch tag.Number {
	case TagAppOTK:
		msg := &AppOTK{}
		err = wrapError(cbor.Unmarshal(tag.Content, msg), "failed cbor.Unmarshal")
		appmsg = msg
	default:
		err = newError("invalid AppMsg tag")
	}
	if nil != err {
		return nil, err
	}
	if v, checkable := appmsg.(checker); checkable {
		err = wrapError(v.Check(), "loaded an invalid msg")
	}

	return appmsg, err
}

// checker is an internal interface for messages that can validate their content.
type checker interface {
	// Check validates the message fields and returns an error if any constraint is violated.
	Check() error
}
