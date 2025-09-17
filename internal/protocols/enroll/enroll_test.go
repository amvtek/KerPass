package enroll

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/credentials"
	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/transport"
)

func TestFsmEnrollSuccess(t *testing.T) {
	cli, srv := makePeerState(t)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	ct := transport.RWTransport{R: c, W: c}
	st := transport.RWTransport{R: s, W: s}

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(cli, ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(srv, st)
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
	count := cli.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed client CardCount control, %d != 1", count)
	}

	// check that server Card was saved
	count = srv.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed server CardCount control, %d != 1", count)
	}

	// check that server Authorization was removed
	count = srv.Repo.AuthorizationCount()
	if 0 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 0", count)
	}
}

func TestFsmEnrollFailAuthorization(t *testing.T) {
	cli, srv := makePeerState(t)

	// change client authorization
	rand.Read(cli.AuthorizationId)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	ct := transport.RWTransport{R: c, W: c, C: c}
	st := transport.RWTransport{R: s, W: s, C: s}

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(cli, ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(srv, st)
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
	count := cli.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed client CardCount control, %d != 0", count)
	}

	// check that no server Card was saved
	count = srv.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed server CardCount control, %d != 0", count)
	}

}

func TestFsmEnrollFailReadClientConfirmation(t *testing.T) {
	cli, srv := makePeerState(t)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)

	// Client transport
	ct := transport.RWTransport{R: c, W: c, C: c}

	// Server transport
	st := transport.NewLimitTransport(transport.RWTransport{R: s, W: s, C: s})
	st.SetReadLimit(3) // server will not be able to read final Client confirmation

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(cli, ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(srv, st)
		result <- err
	}(rs)

	// Unsure Client will reliably detect Server failure as it expects no confirmation.
	// However when using in memory pipe it appears that client fails as the final message
	// is not read by the Server.
	ce := <-rc
	if nil != ce {
		t.Logf("client protocol completed with error status:\n%v", ce)
	} else {
		t.Logf("client protocol detected no error")
	}

	se := <-rs
	if nil == se {
		t.Errorf("server protocol run without error, in spite of expected failure")
	} else {
		t.Logf("server protocol completed with EXPECTED error:\n%v", se)
	}

	// check that no server Card was saved
	count := srv.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed server CardCount control, %d != 0", count)
	}

	// check that authorization was restored
	count = srv.Repo.AuthorizationCount()
	if 1 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 1", count)
	}

}

func TestFsmEnrollFailWriteClientConfirmation(t *testing.T) {
	cli, srv := makePeerState(t)

	// create transports
	deadline := time.Now().Add(500 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)

	// Client MessageTransport
	ct := transport.NewLimitTransport(transport.RWTransport{R: c, W: c, C: c})
	ct.SetWriteLimit(3) // Client will not be able to write final confirmation

	// Server MessageTransport
	st := transport.RWTransport{R: s, W: s, C: s}

	// run client protocol
	rc := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(cli, ct)
		result <- err
	}(rc)

	// run server protocol
	rs := make(chan error, 1)
	go func(result chan<- error) {
		err := protocols.Run(srv, st)
		result <- err
	}(rs)

	ce := <-rc
	if nil == ce {
		t.Errorf("client protocol run without error, in spite of expected failure")
	} else {
		t.Logf("client protocol completed with EXPECTED error:\n%v", ce)
	}

	se := <-rs
	if nil == se {
		t.Errorf("server protocol run without error, in spite of expected failure")
	} else {
		t.Logf("server protocol completed with EXPECTED error:\n%v", se)
	}

	// check that no client Card was saved
	count := cli.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed client CardCount control, %d != 0", count)
	}

	// check that no server Card was saved
	count = srv.Repo.CardCount()
	if 0 != count {
		t.Errorf("failed server CardCount control, %d != 0", count)
	}

	// check that authorization was restored
	count = srv.Repo.AuthorizationCount()
	if 1 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 1", count)
	}

}

func makePeerState(t *testing.T) (*ClientState, *ServerState) {

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

	// create client, server states.
	cli, err := NewClientState(
		ClientCfg{
			RealmId:         realmId,
			AuthorizationId: authorizationId,
			Repo:            clientCredStore,
		},
	)
	if nil != err {
		t.Fatalf("failed creating ClientState, got error %v", err)
	}
	srv, err := NewServerState(
		ServerCfg{
			KeyStore: keyStore,
			Repo:     serverCredStore,
		},
	)
	if nil != err {
		t.Fatalf("failed creating ServerState, got error %v", err)
	}

	return cli, srv
}
