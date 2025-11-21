package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/observability"
	"code.kerpass.org/golang/pkg/credentials"
)

func TestHttpEnrollSuccess(t *testing.T) {
	observability.SetTestDebugLogging(t)

	clicfg, srvhdlr := makePeerConfig(t)

	// starts test server
	srv := httptest.NewServer(observability.Middleware{}.Wrap(srvhdlr))
	defer srv.Close()

	// run enrollment
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := EnrollOverHTTP(ctx, http.DefaultClient, srv.URL, clicfg)
	if nil != err {
		t.Fatalf("Failed EnrollOverHTTP, got error %v", err)
	}

	// check that client Card was saved
	count := clicfg.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed client CardCount control, %d != 1", count)
	}

	// check that server Card was saved
	count, err = srvhdlr.Cfg.Repo.CardCount(ctx)
	if nil != err {
		t.Errorf("failed server CardCount, got error %v", err)
	} else if 1 != count {
		t.Errorf("failed server CardCount control, %d != 1", count)
	}

	// check that server Authorization was removed
	count, err = srvhdlr.Cfg.Repo.AuthorizationCount(ctx)
	if nil != err {
		t.Errorf("failed server AuthorizationCount, got error %v", err)
	} else if 0 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 0", count)
	}
}

func TestHttpEnrollReplaySuccess(t *testing.T) {
	observability.SetTestDebugLogging(t)

	clicfg, srvhdlr := makePeerConfig(t)

	// starts test server
	srv := httptest.NewServer(observability.Middleware{}.Wrap(srvhdlr))
	defer srv.Close()

	// run enrollment
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client := &httpReplayClient{t: t, ReplayStart: 1}
	err := EnrollOverHTTP(ctx, client, srv.URL, clicfg)
	if nil != err {
		t.Fatalf("Failed EnrollOverHTTP, got error %v", err)
	}

	// check that client Card was saved
	count := clicfg.Repo.CardCount()
	if 1 != count {
		t.Errorf("failed client CardCount control, %d != 1", count)
	}

	// check that server Card was saved
	count, err = srvhdlr.Cfg.Repo.CardCount(ctx)
	if nil != err {
		t.Errorf("failed server CardCount, got error %v", err)
	} else if 1 != count {
		t.Errorf("failed server CardCount control, %d != 1", count)
	}

	// check that server Authorization was removed
	count, err = srvhdlr.Cfg.Repo.AuthorizationCount(ctx)
	if nil != err {
		t.Errorf("failed server AuthorizationCount, got error %v", err)
	} else if 0 != count {
		t.Errorf("failed server AuthorizationCount control, %d != 0", count)
	}
}

// statefull httpClient implementation that submit Request multiple times.
// this is to test that HttpSession replay protection is effective.
type httpReplayClient struct {
	t           *testing.T
	ReqCount    int
	ReplayStart int
}

func (self *httpReplayClient) Do(req *http.Request) (*http.Response, error) {
	defer func() { self.ReqCount += 1 }()
	client := http.DefaultClient

	// make sure that req.Body can be read multiple times
	srzbody, err := io.ReadAll(req.Body)
	if nil != err {
		self.t.Fatalf("ReplayClient failed pre reading req.Body, got error %v", err)
	}
	body := bytes.NewReader(srzbody)
	req.Body = io.NopCloser(body)

	resp0, err0 := client.Do(req)

	if self.ReqCount >= self.ReplayStart {
		self.t.Logf("Replaying submitted request")
		body.Seek(0, io.SeekStart)
		resp1, err1 := client.Do(req)
		if (nil == err1) && resp1.StatusCode < 300 {
			self.t.Fatalf("Replay request succeeded, got status %d", resp1.StatusCode)
		} else {
			self.t.Logf("OK, Replay request failed")
		}
	}

	return resp0, err0
}

var _ httpClient = &httpReplayClient{}

func makePeerConfig(t *testing.T) (ClientCfg, *HttpHandler) {

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
	err = keyStore.SaveServerKey(context.Background(), srvKey)
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
	err = serverCredStore.SaveEnrollAuthorization(context.Background(), authorization)
	if nil != err {
		t.Fatalf("failed initializing serverCredStore, got error %v", err)
	}

	// prepare the enrollment handler
	srv, err := NewHttpHandler(keyStore, serverCredStore)
	if nil != err {
		t.Fatalf("failed creating srv handler, got error %v", err)
	}

	// prepare client CredStore
	clientCredStore := credentials.NewMemClientCredStore()

	// create client config
	cli := ClientCfg{
		RealmId:         realmId,
		AuthorizationId: authorizationId,
		Repo:            clientCredStore,
	}

	return cli, srv
}
