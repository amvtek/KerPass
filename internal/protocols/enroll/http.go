package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"code.kerpass.org/golang/internal/protocols"
	"code.kerpass.org/golang/internal/session"
)


type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type httpMsg struct {
	SessionId []byte `cbor:"1,keyasint"`
	Msg       []byte `cbor:"2,keyasint"`
}

func EnrollOverHTTP(ctx context.Context, cli httpClient, serverUrl string, cfg ClientCfg) error {

	// validate serverUrl
	srvUrl, err := url.Parse(serverUrl)
	if nil != err {
		return wrapError(err, "invalid serverUrl")
	}
	if !slices.Contains([]string{"http", "https"}, srvUrl.Scheme) {
		return newError("invalid serverUrl scheme %s", srvUrl.Scheme)
	}

	// construct ClientState
	cs, err := NewClientState(cfg)
	if nil != err {
		return wrapError(err, "failed ClientState construction")
	}
	state, stateFunc := cs.State()

	var srzmsg, srvmsg, climsg, sessionId []byte
	var hm httpMsg
	var req *http.Request
	var resp *http.Response
	var errProto, errIO error
	for step := range 3 {
		stateFunc, climsg, errProto = stateFunc(state, srvmsg)
		if nil == climsg {
			break
		}

		hm = httpMsg{SessionId: sessionId, Msg: climsg}
		srzmsg, err = cborSrz.Marshal(hm)
		if nil != err {
			errIO = wrapError(err, "[%d] failed serializing httpMsg", step)
			break
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, serverUrl, bytes.NewReader(srzmsg))
		if nil != err {
			errIO = wrapError(err, "[%d] failed instantiating http Request", step)
			break
		}
		req.Header.Add("Content-Type", "application/cbor")
		resp, err = cli.Do(req)
		if nil != err {
			errIO = wrapError(err, "failed http POST request")
			break
		}
		if resp.StatusCode >= 300 || resp.StatusCode < 200 {
			errIO = newError("[%d] failed http POST request, got status %d", step, resp.StatusCode)
			break
		}
		srzmsg, err = io.ReadAll(resp.Body)
		if nil != err {
			errIO = wrapError(err, "[%d] failed reading resp.Body", step)
			break
		}
		hm = httpMsg{}
		err = cborSrz.Unmarshal(srzmsg, &hm)
		if nil != err {
			errIO = wrapError(err, "[%d] failed deserializing resp.Body", step)
			break
		}
		sessionId = hm.SessionId
		if 0 == len(sessionId) {
			errIO = newError("[%d] invalid server response miss sessionId", step)
			break
		}
		srvmsg = hm.Msg
	}

	if nil == errProto {
		errProto = newError("invalid protocol status")
	}

	if errors.Is(errProto, protocols.OK) && nil == errIO {
		err = nil
	} else {
		err = errors.Join(errProto, errIO)
	}

	return err
}
