package slp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"code.kerpass.org/golang/pkg/credentials"
	"code.kerpass.org/golang/pkg/ephemsec"
	"code.kerpass.org/golang/pkg/protocols/enroll"
)

const (
	schOtpE1S1 = iota
	schOtpE1S2
	schOtkE1S2
	schOtkE2S2
	schSize
)

var schemes = [schSize]uint16{
	schOtpE1S1: ephemsec.SHA512_X25519_E1S1_T600B10P8,
	schOtpE1S2: ephemsec.SHA512_X25519_E1S2_T600B32P9,
	schOtkE1S2: ephemsec.SHA512_X25519_E1S2_T1024B256P33,
	schOtkE2S2: ephemsec.SHA512_X25519_E2S2_T1024B256P33,
}

var uidCount = &atomic.Uint32{}

func TestSlpDirect(t *testing.T) {
	var testname string

	st := newStage(t)
	for i, schref := range schemes {
		sch, err := ephemsec.GetScheme(schref)
		if nil != err {
			t.Fatalf("failed loading scheme #%d", i)
		}
		for _, desync := range []float64{-1.5, -0.95, -0.5, 0, 0.5, 0.95, 1.5} {
			switch {
			case desync < 0:
				testname = fmt.Sprintf("%s@[T-%.2f]", sch.Name(), math.Abs(desync))
			case desync == 0:
				testname = fmt.Sprintf("%s@[T]", sch.Name())
			case desync > 0:
				testname = fmt.Sprintf("%s@[T+%.2f]", sch.Name(), desync)
			}
			t.Run(testname, func(t *testing.T) {
				ccr, err := st.NewCardChallengeRequest(i)
				if nil != err {
					t.Fatalf("failed instantiating CardChallengeRequest, got error %v", err)
				}
				cc := CardChallenge{}
				err = GetCardChallenge(
					context.Background(),
					http.DefaultClient,
					st.GetChalUrl(),
					ccr,
					&cc,
				)
				if nil != err {
					t.Fatalf("failed obtaining CardChallenge, got error %v", err)
				}

				// calculates the otp
				aac := AgentAuthContext{
					SelectedProtocol:     SlpDirect,
					SessionId:            cc.SessionId,
					StaticKeyCert:        cc.StaticKeyCert,
					AppContextUrl:        fmt.Sprintf("https://demo%02d.kerpass.org/start-login", i),
					AuthServerGetChalUrl: "https://ats.kerpass.org/get-card-chal",
					AuthServerLoginUrl:   cc.AuthServerLoginUrl,
					AppStartUrl:          cc.AppStartUrl,
				}
				ach, err := aac.Sum(nil)
				if nil != err {
					t.Fatalf("failed hashing AgentAuthContext, got error %v", err)
				}
				ach, err = EphemSecContextHash(ccr.RealmId, ach, nil)
				if nil != err {
					t.Fatalf("failed ephemsec context hashing, got error %v", err)
				}
				var ephemkey *ecdh.PrivateKey
				if "E2S2" == sch.KeyExchangePattern() {
					curve := ecdh.X25519()
					ephemkey, err = curve.GenerateKey(rand.Reader)
					if nil != err {
						t.Fatalf("failed generating client ephemeral key, got error %v", err)
					}
				}
				ts := time.Now().Unix() + int64(math.Round(sch.T()*0.5*desync))
				eps := ephemsec.State{
					Context:         ach,
					Nonce:           cc.INonce,
					Time:            ts,
					EphemKey:        ephemkey,
					StaticKey:       st.card.Kh.PrivateKey,
					RemoteEphemKey:  cc.E.PublicKey,
					RemoteStaticKey: cc.S.PublicKey,
					Psk:             st.card.Psk,
				}
				otp, err := eps.EPHEMSEC(sch, ephemsec.Responder, nil)
				if nil != err {
					t.Fatalf("failed client OTP calculation, got error %v", err)
				}
				dlr := DirectLoginRequest{SessionId: cc.SessionId, Otp: otp}
				if nil != ephemkey {
					dlr.E.PublicKey = ephemkey.PublicKey()
				}
				if 256 == sch.B() {
					// OTK case
					dlr.CardId = st.card.IdToken
				} else {
					// OTP case
					dlr.CardId = []byte(st.card.UserId)
				}
				valid, err := DirectCheckOtp(
					context.Background(),
					http.DefaultClient,
					st.DirectLoginUrl(),
					&dlr,
				)
				if nil != err {
					t.Fatalf("failed DirectCheckOtp, got error %v", err)
				}
				if math.Abs(desync) < 1.0 {
					if !valid {
						t.Error("Invalid OTP")
					}
				} else {
					if valid {
						t.Error("valid OTP with out of window timestamp")
					}
				}
			})

		}
	}

}

type stage struct {
	realmId []byte
	card    *credentials.Card
	server  *httptest.Server
}

// NewCardChallengeRequest generates a CardChallengeRequest that the test server will accept.
// The schref parameter determines the EPHEMSEC scheme that will be used for authentication.
func (self *stage) NewCardChallengeRequest(schref int) (*CardChallengeRequest, error) {
	if schref < 0 || schref >= schSize {
		return nil, wrapError(ErrValidation, "invalid schref")
	}
	ccr := CardChallengeRequest{
		RealmId:        self.realmId,
		SelectedMethod: AuthMethod{Protocol: SlpDirect, Scheme: schemes[schref]},
		AppContextUrl:  fmt.Sprintf("https://demo%02d.kerpass.org/start-login", schref),
	}

	return &ccr, nil
}

// GetChalUrl returns the /get-card-chal url on the test server.
func (self *stage) GetChalUrl() string {
	return fmt.Sprintf("%s/get-card-chal", self.server.URL)
}

// DirectLoginUrl returns the /slp-direct url on the test server.
func (self *stage) DirectLoginUrl() string {
	return fmt.Sprintf("%s/slp-direct", self.server.URL)
}

func newStage(t *testing.T) *stage {

	// ---
	// create the stores
	ctx := context.Background()
	sks := credentials.NewMemKeyStore()
	scs, err := credentials.NewMemServerCredStore()
	if nil != err {
		t.Fatalf("failed instantiating scs, got error %v", err)
	}

	// ---
	// register Realm
	realmId := [32]byte{1, 2, 3, 4}
	rlm := credentials.Realm{RealmId: realmId[:], AppName: "Test App"}
	err = scs.SaveRealm(ctx, &rlm)
	if nil != err {
		t.Fatalf("failed saving realm, got error %v", err)
	}

	// ---
	// generate Realm static key

	// the same key is used in different contexts (enroll & otp generation)
	// in production each usage context shall have a different key...
	curve := ecdh.X25519()
	seckey, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating realm static key, got error %v", err)
	}
	sk := credentials.ServerKey{RealmId: realmId[:], Certificate: []byte("TBD")}
	sk.Kh.PrivateKey = seckey

	// ---
	// register Realm keys

	// enroll key
	err = sks.SaveServerKey(ctx, enroll.SrvKeyName, sk)
	if nil != err {
		t.Fatalf("failed registering realm enroll key, got error %v", err)
	}

	// scheme keys
	var sch *ephemsec.Scheme
	for i, schref := range schemes[1:] {
		sch, err = ephemsec.GetScheme(schref)
		if nil != err {
			t.Fatalf("failed loading scheme #%d, got error %v", i+1, err)
		}
		err = sks.SaveServerKey(ctx, sch.Name(), sk)
		if nil != err {
			t.Fatalf("failed registering realm scheme #%d key, got error %v", i+1, err)
		}
	}

	// ---
	// create client/server cards

	cc := credentials.Card{}
	sc := credentials.ServerCard{}
	err = initCards(&rlm, &cc, &sc)
	if nil != err {
		t.Fatalf("failed cards initialization, got error %v", err)
	}
	err = scs.SaveCard(ctx, cc.IdToken, &sc)
	if nil != err {
		t.Fatalf("failed saving server card, got error %v", err)
	}

	// ---
	// generate client ephemeral key

	// ---
	// create ChallengeFactory

	acx := AuthContext{
		RealmId:              realmId,
		AuthServerGetChalUrl: "https://ats.kerpass.org/get-card-chal",
		AuthServerLoginUrl:   "https://ats.kerpass.org/slp-direct",
		AppStartUrl:          "http://demo.kerpass.local",
	}
	var acs []AuthContext
	for pos, schref := range schemes {
		acx.AuthMethod = AuthMethod{Protocol: SlpDirect, Scheme: schref}
		acx.AppContextUrl = fmt.Sprintf("https://demo%02d.kerpass.org/start-login", pos)
		acs = append(acs, acx)
	}

	chf, err := NewChallengeFactoryImpl(5*time.Minute, sks, scs, acs)
	if nil != err {
		t.Fatalf("failed ChallengeFactory creation, got error %v", err)
	}

	// ---
	// register server endpoints
	mux := http.NewServeMux()

	// get-card-chal endpoint
	getCardChalHdlr, err := NewCardChallengeEndpoint(chf)
	if nil != err {
		t.Fatalf("failed creating the CardChallenge endpoint, got error %v", err)
	}
	mux.Handle("POST /get-card-chal", getCardChalHdlr)

	// slp-direct endpoint
	slpDirectHdlr, err := NewDirectEndpoint(chf)
	if nil != err {
		t.Fatalf("failed creating the slp Direct endpoint, got error %v", err)
	}
	mux.Handle("POST /slp-direct", slpDirectHdlr)

	// start test server
	srv := httptest.NewServer(mux)

	return &stage{realmId: realmId[:], card: &cc, server: srv}
}

// initCards initializes a pair of client/server cards.
// the client Card does not have a UserId, hence IdToken shall be used for OTP & OTK authentication.
func initCards(rl *credentials.Realm, cc *credentials.Card, sc *credentials.ServerCard) error {
	if nil == rl || nil == cc || nil == sc {
		return wrapError(ErrValidation, "nil arguments")
	}
	cc.ID = 0

	// ---
	// realm

	cc.RealmId = rl.RealmId
	cc.AppName = rl.AppName
	cc.AppDesc = rl.AppDesc
	cc.AppLogo = rl.AppLogo
	sc.RealmId = rl.RealmId

	// ---
	// UserId & idToken
	idh, err := credentials.NewIdHasher(nil)
	if nil != err {
		return wrapError(err, "failed IdHasher instantation")
	}
	cc.UserId = fmt.Sprintf("card-%04d", uidCount.Add(1))
	idtkn, err := idh.IdTokenOfUserId(rl.RealmId, cc.UserId, nil)
	if nil != err {
		return wrapError(err, "failed card IdToken derivation")
	}
	cc.IdToken = idtkn

	// ---
	// keypair
	curve := ecdh.X25519()
	keypair, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		return wrapError(err, "failed card keypair generation")
	}

	cc.Kh.PrivateKey = keypair
	sc.Kh.PublicKey = keypair.PublicKey()

	// ---
	// psk
	psk := make([]byte, 32)
	rand.Read(psk)

	cc.Psk = psk
	sc.Psk = psk

	return nil
}
