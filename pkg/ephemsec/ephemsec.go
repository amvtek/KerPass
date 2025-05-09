package ephemsec

import (
	"io"
	"slices"

	"golang.org/x/crypto/hkdf"
)

type role bool

const (
	Initiator = role(true)
	Responder = role(false)
)

// EPHEMSEC executes the KerPass ephemeral secret generation algorithm and returns the
// generated secret.
//
// If a non nil dst buffer is passed, EPHEMSEC will try reusing it to output the
// generated secret. If dst is nil, EPHEMSEC will allocate memory to hold the
// generated secret.
func (self *State) EPHEMSEC(scheme *scheme, role role, dst []byte) ([]byte, error) {
	if nil == scheme || !scheme.init || nil == self {
		return nil, newError("invalid state")
	}
	sch := *scheme

	err := self.setContext(sch)
	if nil != err {
		return nil, wrapError(err, "failed setContext")
	}
	err = self.setPTime(sch, role)
	if nil != err {
		return nil, wrapError(err, "failed setPTime")
	}
	err = self.setInfo()
	if nil != err {
		return nil, wrapError(err, "failed setInfo")
	}
	err = self.runDH(sch, role)
	if nil != err {
		return nil, wrapError(err, "failed runDH")
	}

	// adjust dst buffer to hold HKDF intermediary key
	switch sch.B {
	case 256:
		dst = slices.Grow(dst[:0], sch.P)
		dst = dst[:sch.P]
	default:
		dst = slices.Grow(dst[:0], 8)
		dst = dst[:8]
	}

	// run HKDF
	secret := self.ikm[:self.ikmcursor]
	salt := self.context[:self.contextcursor]
	info := self.info[:self.infocursor]
	krd := hkdf.New(sch.hash.New, secret, salt, info)
	_, err = io.ReadFull(krd, dst)
	if nil != err {
		return nil, wrapError(err, "failed HKDF key filling")
	}

	return sch.NewOTP(dst, self.ptime)
}

// runDH run the scheme Diffie-Hellmann key exchanges using state keys and save the resulting
// secrets into the state. It appends the state Psk to such secrets.
func (self *State) runDH(sch scheme, role role) error {

	var keyexch string
	switch role {
	case Initiator:
		keyexch = "I" + sch.K
	case Responder:
		keyexch = "R" + sch.K
	}

	// alias the DH exchange keys
	// e, s names are from noise protocol
	e := self.EphemKey
	s := self.StaticKey
	rE := self.RemoteEphemKey
	rS := self.RemoteStaticKey

	ikm := self.ikm[:0]
	var z []byte
	var err error

	switch keyexch {
	case "IE1S1":
		// initiator has e, responder has forwarded rS
		z, err = sch.ecdh(e, rS)
		if nil != err {
			return wrapError(err, "failed ecdh(e, rS)")
		}
		ikm = append(ikm, z...)

	case "RE1S1":
		// responder has s, initiator has forwarded rE
		z, err = sch.ecdh(s, rE)
		if nil != err {
			return wrapError(err, "failed ecdh(s, rE)")
		}
		ikm = append(ikm, z...)

	case "IE1S2":
		// Initiator has e & s. Responder has forwarded rS
		z, err = sch.ecdh(e, rS)
		if nil != err {
			return wrapError(err, "failed ecdh(e, rS)")
		}
		ikm = append(ikm, z...)
		z, err = sch.ecdh(s, rS)
		if nil != err {
			return wrapError(err, "failed ecdh(s, rS)")
		}
		ikm = append(ikm, z...)

	case "RE1S2":
		// Responder has s. Initiator has forwarded rE, rS
		z, err = sch.ecdh(s, rE)
		if nil != err {
			return wrapError(err, "failed ecdh(s, rE)")
		}
		ikm = append(ikm, z...)
		z, err := sch.ecdh(s, rS)
		if nil != err {
			return wrapError(err, "failed ecdh(s, rS)")
		}
		ikm = append(ikm, z...)

	case "IE2S2", "RE2S2":
		// Initiator and Responder have e & s.
		z, err = sch.ecdh(e, rE)
		if nil != err {
			return wrapError(err, "failed ecdh(e, rE)")
		}
		ikm = append(ikm, z...)
		z, err = sch.ecdh(s, rS)
		if nil != err {
			return wrapError(err, "failed ecdh(s, rS)")
		}
		ikm = append(ikm, z...)

	default:
		// unreachable if properly initialized
		return newError("scheme has invalid K %s", sch.K)
	}

	psz := len(self.Psk)
	if psz < minPSK || psz > maxPSK {
		return newError("Psk length %d not in %d..%d range", psz, minPSK, maxPSK)
	}
	ikm = append(ikm, self.Psk...)

	isz := len(ikm)
	if isz > maxIKM {
		return newError("ikm buffer overflow")
	}
	self.ikmcursor = isz

	return nil
}
