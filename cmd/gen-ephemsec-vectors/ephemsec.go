package main

import (
	"crypto"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand/v2"

	"golang.org/x/crypto/hkdf"

	"code.kerpass.org/golang/internal/utils"
	"code.kerpass.org/golang/pkg/ephemsec"
)

var rng *rand.ChaCha8 // see init at the bottom of this file

// Below code implements EPHEMSEC for the Responder role, without the extensive error
// checking and memory reuse optimizations in the ephemsec package.
// The goal is to deliver EPHEMSEC test vectors with minimal effort.

func fillVector(schemename string, vect *ephemsec.TestVector) error {
	if nil == vect {
		return fmt.Errorf("nil vect")
	}

	// load the scheme
	scheme, err := ephemsec.NewScheme(schemename)
	if nil != err {
		return fmt.Errorf("Failed scheme parsing, got error %w", err)
	}
	vect.SchemeName = scheme.Name()

	// generate DH keys & DH shared secret
	curve := scheme.Curve()
	var IStaticKey, REphemKey *ecdh.PrivateKey
	var Z []byte
	IEphemKey, err := curve.GenerateKey(rng)
	if nil != err {
		return fmt.Errorf("Failed generating Initiator Ephemeral key, got error %w", err)
	}
	vect.InitiatorEphemKey = utils.HexBinary(IEphemKey.Bytes())
	vect.ResponderRemoteEphemKey = utils.HexBinary(IEphemKey.PublicKey().Bytes())
	RStaticKey, err := curve.GenerateKey(rng)
	if nil != err {
		return fmt.Errorf("Failed generating Responder Static key, got error %w", err)
	}
	vect.ResponderStaticKey = utils.HexBinary(RStaticKey.Bytes())
	vect.InitiatorRemoteStaticKey = utils.HexBinary(RStaticKey.PublicKey().Bytes())
	switch scheme.KeyExchangePattern() {
	case "E1S1":
		Z, err = doE1S1(RStaticKey, IEphemKey.PublicKey())
		if nil != err {
			return fmt.Errorf("Failed E1S1 Key exchange, got error %w", err)
		}
	case "E1S2":
		IStaticKey, err = curve.GenerateKey(rng)
		if nil != err {
			return fmt.Errorf("Failed generating Initiator Static key, got error %w", err)
		}
		vect.InitiatorStaticKey = utils.HexBinary(IStaticKey.Bytes())
		vect.ResponderRemoteStaticKey = utils.HexBinary(IStaticKey.PublicKey().Bytes())
		Z, err = doE1S2(RStaticKey, IEphemKey.PublicKey(), IStaticKey.PublicKey())
		if nil != err {
			return fmt.Errorf("Failed E1S2 Key exchange, got error %w", err)
		}
	case "E2S2":
		IStaticKey, err = curve.GenerateKey(rng)
		if nil != err {
			return fmt.Errorf("Failed generating Initiator Static key, got error %w", err)
		}
		vect.InitiatorStaticKey = utils.HexBinary(IStaticKey.Bytes())
		vect.ResponderRemoteStaticKey = utils.HexBinary(IStaticKey.PublicKey().Bytes())
		REphemKey, err = curve.GenerateKey(rng)
		if nil != err {
			return fmt.Errorf("Failed generating Responder Ephemeral key, got error %w", err)
		}
		vect.ResponderEphemKey = utils.HexBinary(REphemKey.Bytes())
		vect.InitiatorRemoteEphemKey = utils.HexBinary(REphemKey.PublicKey().Bytes())
		Z, err = doE2S2(REphemKey, RStaticKey, IEphemKey.PublicKey(), IStaticKey.PublicKey())
		if nil != err {
			return fmt.Errorf("Failed E2S2 Key exchange, got error %w", err)
		}
	default:
		return fmt.Errorf("Invalid KeyExchange pattern %s", scheme.KeyExchangePattern())
	}

	// generate shared psk
	psk := make([]byte, 32)
	rng.Read(psk) // rng.Read can not fail
	vect.Psk = utils.HexBinary(psk)
	Z = append(Z, psk...)

	// generate Initiator nonce
	nsz := 16 + rand.IntN(64-16)
	nonce := make([]byte, nsz)
	rng.Read(nonce)
	vect.InitiatorNonce = utils.HexBinary(nonce)

	// generate shared context
	csz := rand.IntN(64)
	var context []byte
	if csz > 0 {
		context = make([]byte, csz)
		rng.Read(context)
	}
	vect.Context = utils.HexBinary(context)

	// generate responder time
	var rt int64
	if rand.Float64() < 0.1 {
		// in 10% of the case, rt is a 'real' int64
		rt = rand.Int64()
	} else {
		// in 90% of the case, rt only has 32 bits
		// this is what we expect when rt is Unix time
		rt = int64(rand.Uint32())
	}
	ptime, sync := scheme.Time(rt)
	vect.ResponderTime = rt
	vect.ResponderSynchroHint = sync

	// generate initiator time
	tw := scheme.TimeWindow()
	step := math.Ceil(tw / float64(scheme.DigitBase()))
	// TODO: we substract step from tw due to an issue with current synchronization algorithm
	vect.InitiatorTime = rt - int64(tw/2) + rand.Int64N(int64(tw-step))

	// generate the shared secret
	salt := makeSalt(context, scheme.Name())
	info := makeInfo(nonce, ptime)
	secret, err := makeOTP( scheme.Hash(), scheme.DigitBase(), scheme.CodeSize(), Z, salt, info)
	if nil != err {
		return fmt.Errorf("Failed generating the shared secret, got error %w", err)
	}
	secret = append(secret, byte(sync)) // Add final synchro digit
	vect.SharedSecret = utils.HexBinary(secret)
	if 256 != scheme.DigitBase() {
		otp, err := ephemsec.B32Alphabet.Format(secret, 0, ' ')
		if nil != err {
			return fmt.Errorf("Failed alphabet.Format, got error %v", err)
		}
		vect.Otp = otp
	}
	return nil
}

// doE1S1 run Responder E1S1 EPHEMSEC key exchange and return the DH shared secret
func doE1S1(s *ecdh.PrivateKey, rE *ecdh.PublicKey) ([]byte, error) {
	return s.ECDH(rE)
}

// doE1S2 run Responder E1S2 EPHEMSEC key exchange and return the DH shared secret
func doE1S2(s *ecdh.PrivateKey, rE *ecdh.PublicKey, rS *ecdh.PublicKey) ([]byte, error) {
	var Z []byte

	Ze, err := s.ECDH(rE)
	if nil != err {
		return nil, fmt.Errorf("Failed s.ECDH(rE), got error %w", err)
	}
	Z = append(Z, Ze...)

	Zs, err := s.ECDH(rS)
	if nil != err {
		return nil, fmt.Errorf("Failed s.ECDH(rS), got error %w", err)
	}
	Z = append(Z, Zs...)

	return Z, nil

}

// doE2S2 run Responder E2S2 EPHEMSEC key exchange and return the DH shared secret
func doE2S2(e *ecdh.PrivateKey, s *ecdh.PrivateKey, rE *ecdh.PublicKey, rS *ecdh.PublicKey) ([]byte, error) {
	var Z []byte

	Ze, err := e.ECDH(rE)
	if nil != err {
		return nil, fmt.Errorf("Failed e.ECDH(rE), got error %w", err)
	}
	Z = append(Z, Ze...)

	Zs, err := s.ECDH(rS)
	if nil != err {
		return nil, fmt.Errorf("Failed s.ECDH(rS), got error %w", err)
	}
	Z = append(Z, Zs...)

	return Z, nil
}

func makeSalt(context []byte, schemename string) []byte {
	rv := make([]byte, 0, 2+len(context)+2+len(schemename))
	rv = append(rv, byte('C'))
	rv = append(rv, byte(len(context)))
	rv = append(rv, context...)
	rv = append(rv, byte('S'))
	rv = append(rv, byte(len(schemename)))
	rv = append(rv, []byte(schemename)...)
	return rv
}

func makeInfo(nonce []byte, ptime int64) []byte {
	rv := make([]byte, 0, 2+len(nonce)+10)
	rv = append(rv, byte('N'))
	rv = append(rv, byte(len(nonce)))
	rv = append(rv, byte('T'))
	rv = append(rv, 8)
	rv = binary.BigEndian.AppendUint64(rv, uint64(ptime))
	return rv
}

// return OTP/OTK in digit form without synchro digit
func makeOTP(hash crypto.Hash, base int, codesize int, ikm []byte, salt []byte, info []byte) ([]byte, error) {
	var outsize int
	switch base {
	case 256:
		outsize = codesize
	case 10, 16, 32:
		outsize = 8
	default:
		return nil, fmt.Errorf("Invalid codesize %d", codesize)
	}
	outkey := make([]byte, outsize)

	// use HKDF to fill outkey
	keyrdr := hkdf.New(hash.New, ikm, salt, info)
	_, err := io.ReadFull(keyrdr, outkey)
	if nil != err {
		return nil, fmt.Errorf("Failed HKDF key filling, got error %w", err)
	}
	if 256 == base {
		return outkey, nil
	}

	maxcode := uint64(math.Pow(float64(base), float64(codesize)))
	B := uint64(base)
	icode := binary.BigEndian.Uint64(outkey) % maxcode // outkey has length 8
	otp := make([]byte, codesize)
	for i := range codesize {
		otp[codesize-1-i] = byte(icode % B)
		icode /= B
	}

	return otp, nil
}

func init() {
	var seed [32]byte
	copy(seed[:32], []byte("KerPass_EPHEMSEC"))
	rng = rand.NewChaCha8(seed)
}
