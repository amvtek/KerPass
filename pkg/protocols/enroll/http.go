package enroll

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"code.kerpass.org/golang/internal/observability"
	"code.kerpass.org/golang/internal/session"
	"code.kerpass.org/golang/pkg/protocols"
)

// HttpSession allows synchronized access to enroll ServerState.
type HttpSession struct {
	mut   *sync.Mutex
	state *ServerState
}

// HttpHandler holds configuration & state necessary for executing the enroll server protocol.
type HttpHandler struct {
	Cfg          ServerCfg
	SessionStore *session.MemStore[session.Sid, HttpSession]
}

// ServeHTTP update enroll ServerState using message in incoming request.
// ServeHTTP restore session ServerState in case of error.
func (self HttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var errmsg string
	log := observability.GetObservability(r.Context()).Log().With("handler", "enroll")

	// read incoming httpMsg
	srzmsg, err := io.ReadAll(r.Body)
	if nil != err {
		errmsg = "failed reading request body"
		log.Error(errmsg, "error", err)
		writeError(w, http.StatusBadRequest, errmsg)
		return
	}
	hm := httpMsg{}
	err = cborSrz.Unmarshal(srzmsg, &hm)
	if nil != err {
		errmsg = "failed deserializing CBOR"
		log.Error(errmsg, "error", err)
		writeError(w, http.StatusBadRequest, errmsg)
		return
	}

	// success is true only if the handler runs until completion without error.
	// success is read by deferred functions.
	var success bool

	// read session
	var sessionId session.Sid
	var s HttpSession
	var found bool
	if 0 == len(hm.SessionId) {
		// starts new session
		log.Debug("starting new HTTP session")
		state, err := NewServerState(self.Cfg)
		if nil != err {
			errmsg = "invalid configuration"
			log.Error(errmsg, "error", err)
			writeError(w, http.StatusInternalServerError, errmsg)
			return
		}
		s.mut = new(sync.Mutex)
		s.state = state
	} else {
		// retrieve existing session
		copy(sessionId[:], hm.SessionId)
		s, found = self.SessionStore.Get(sessionId)
		if !found {
			errmsg = "invalid session"
			log.Error(errmsg, "sId", hex.EncodeToString(hm.SessionId))
			writeError(w, http.StatusBadRequest, errmsg)
			return
		}
		log.Debug("reloaded HTTP session", "sId", hex.EncodeToString(hm.SessionId))
	}

	// lock the session if it exists
	if found {
		s.mut.Lock()
		defer s.mut.Unlock()
	}

	var bkupState ServerState
	state, sf := s.state.State()
	bkupState = *state
	sf, rmsg, err := sf(r.Context(), state, hm.Msg)
	defer func() {
		if success {
			s.state.SetState(sf)
		} else {
			s.state = &bkupState
		}
	}()
	if (nil != err) && !errors.Is(err, protocols.OK) {
		errmsg = "protocol error"
		log.Error(errmsg, "error", err)
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	status := http.StatusOK
	if errors.Is(err, protocols.OK) {
		status = http.StatusCreated
		defer func() {
			if success {
				log.Debug("clearing HTTP session", "sId", hex.EncodeToString(sessionId[:]))
				self.SessionStore.Pop(sessionId)
			}
		}()
	}

	if !found {
		log.Debug("saving new HTTP session")
		sessionId, err = self.SessionStore.Save(s)
		if nil != err {
			errmsg = "error saving session"
			log.Error(errmsg, "error", err)
			writeError(w, http.StatusInternalServerError, errmsg)
			return
		}
		hm.SessionId = sessionId[:]
		defer func() {
			if !success {
				// if we fail the newly created session is useless
				// as the new sessionId was never forwarded to the client...
				self.SessionStore.Pop(sessionId)
			}
		}()
	}

	hm.Msg = rmsg
	srzmsg, err = cborSrz.Marshal(hm)
	if nil != err {
		errmsg = "failed CBOR serialization"
		log.Error(errmsg, "error", err)
		writeError(w, http.StatusInternalServerError, errmsg)
		return
	}

	w.Header().Add("Content-Type", "application/cbor")
	w.WriteHeader(status)
	_, err = w.Write(srzmsg)
	if nil == err {
		success = true
	} else {
		log.Error("failed meanwhile delivering the HTTP response", "error", err)
	}
}

// writeError writes an error HTTP response to w.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(status)
	io.WriteString(w, msg)
}

// httpClient is a private interface that simplify mocking http.Client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpMsg is used to transport request/response of Enroll client & server.
type httpMsg struct {
	SessionId []byte `cbor:"1,keyasint"`
	Msg       []byte `cbor:"2,keyasint"`
}

// EnrollOverHTTP runs the enroll client protocol over HTTP transport.
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
		stateFunc, climsg, errProto = stateFunc(ctx, state, srvmsg)
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
