package enroll

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/transport"
)

func TestEnrollSuccess(t *testing.T) {
	cliProto, srvProto := makeProtocols(t)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	ct := transport.MessageTransport{S: transport.CBORSerializer{}, Transport: transport.RWTransport{R: c, W: c}}
	st := transport.MessageTransport{S: transport.CBORSerializer{}, Transport: transport.RWTransport{R: s, W: s}}

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		err := cliProto.Run(ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		err := srvProto.Run(st)
		result <- err
	}(rs)

	ce := <-rc
	if nil != ce {
		t.Errorf("failed client protocol, got error %v", ce)
	}

	se := <-rs
	if nil != se {
		t.Errorf("failed server protocol, got error %v", se)
	}

	// check that client Card was saved
	count := cliProto.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed client CardCount control, %d != 1", count)
	}

	// check that server Card was saved
	count = srvProto.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed server CardCount control, %d != 1", count)
	}

	// check that server Authorization was removed
	count = srvProto.Repo.AuthorizationCount()
	if 0 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 0", count)
	}
}

func TestEnrollFailAuthorization(t *testing.T) {
	cliProto, srvProto := makeProtocols(t)

	// change client authorization
	rand.Read(cliProto.AuthorizationId)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	ct := transport.MessageTransport{S: transport.CBORSerializer{}, Transport: transport.RWTransport{R: c, W: c, C: c}}
	st := transport.MessageTransport{S: transport.CBORSerializer{}, Transport: transport.RWTransport{R: s, W: s, C: s}}

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		defer ct.Close()
		err := cliProto.Run(ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		defer st.Close()
		err := srvProto.Run(st)
		result <- err
	}(rs)

	ce := <-rc
	if nil == ce {
		t.Errorf("client protocol run without error, in spite of invalid authorization")
	} else {
		t.Logf("client protocol completed with EXPECTED error:\n%v", ce)
	}

	se := <-rs
	if nil == se {
		t.Errorf("server protocol run without error, in spite of invalid authorization")
	} else {
		t.Logf("server protocol completed with EXPECTED error:\n%v", se)
	}

	// check that no client Card was saved
	count := cliProto.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed client CardCount control, %d != 0", count)
	}

	// check that no server Card was saved
	count = srvProto.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed server CardCount control, %d != 0", count)
	}

}

func makeProtocols(t *testing.T) (ClientEnrollProtocol, ServerEnrollProtocol) {
	// generate realmId
	realmId := make([]byte, 32)
	rand.Read(realmId)

	// generate srvKey
	curve := noiseCfg.CurveAlgo
	sk, err := curve.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("failed generating sk, got error %v", err)
	}
	srvKey := credentials.ServerKey{RealmId: realmId, Certificate: []byte("todo-not-used")}
	srvKey.Kh.PrivateKey = sk

	// prepare server KeyStore
	keyStore := credentials.NewMemKeyStore()
	err = keyStore.SaveServerKey(srvKey)
	if nil != err {
		t.Fatalf("failed initializing keyStore, got error %v", err)
	}

	// generate authorization
	authorizationId := make([]byte, 32)
	rand.Read(authorizationId)
	authorization := credentials.EnrollAuthorization{
		AuthorizationId: authorizationId,
		RealmId:         realmId,
		AppName:         "User Read This",
	}

	// prepare server CredStore
	serverCredStore := credentials.NewMemServerCredStore()
	err = serverCredStore.SaveEnrollAuthorization(authorization)
	if nil != err {
		t.Fatalf("failed initializing serverCredStore, got error %v", err)
	}

	// prepare client CredStore
	clientCredStore := credentials.NewMemClientCredStore()

	// create client, server protocol runners.
	cliProto := ClientEnrollProtocol{
		RealmId:         realmId,
		AuthorizationId: authorizationId,
		Repo:            clientCredStore,
	}
	srvProto := ServerEnrollProtocol{
		KeyStore: keyStore,
		Repo:     serverCredStore,
	}

	return cliProto, srvProto
}
