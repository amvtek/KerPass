package slp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"net/http"

	"code.kerpass.org/golang/pkg/credentials"
)

const (
	maxCardChallengeRequestSize = 512
	maxSlpDirectRequestSize     = 512
)

// CardChallengeEndpoint implements http.Handler to process authentication challenge requests.
// It decodes the CBOR-encoded CardChallengeRequest, delegates challenge generation
// to the configured ChallengeFactory, and returns the CBOR-encoded CardChallenge.
type CardChallengeEndpoint struct {
	factory ChallengeFactory
}

// NewCardChallengeEndpoint constructs a new CardChallengeEndpoint with the given factory.
// Returns an error if factory is nil or fails its optional Check() validation.
func NewCardChallengeEndpoint(factory ChallengeFactory) (*CardChallengeEndpoint, error) {
	if factory == nil {
		return nil, wrapError(ErrValidation, "nil factory")
	}

	// validate factory if it implements Checker
	if fc, ok := factory.(interface{ Check() error }); ok {
		if err := fc.Check(); err != nil {
			return nil, wrapError(err, "failed factory validation")
		}
	}

	return &CardChallengeEndpoint{
		factory: factory,
	}, nil
}

// ServeHTTP handles incoming POST requests carrying a CBOR-encoded CardChallengeRequest.
// It enforces the POST method, reads and decodes the request body, generates a CardChallenge,
// and writes back a CBOR-encoded CardChallenge response.
func (self *CardChallengeEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce POST method
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Read the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxCardChallengeRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 3. Unmarshal CBOR payload into CardChallengeRequest
	// ctapSrz.Unmarshal calls req.Check() automatically.
	var req CardChallengeRequest
	if err := ctapSrz.Unmarshal(body, &req); err != nil {
		http.Error(w, "failed to decode cbor request", http.StatusBadRequest)
		return
	}

	// 4. Generate the CardChallenge using the factory
	var resp CardChallenge
	if err := self.factory.GetCardChallenge(&req, &resp); err != nil {
		// If the factory returns an error, we assume Internal Server Error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Marshal the response to CBOR
	data, err := ctapSrz.Marshal(&resp)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	// 6. Return the response
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// DirectEndpoint implements http.Handler for the SlpDirect authentication protocol.
// It receives a CBOR-encoded DirectLoginRequest, derives the expected OTP server-side
// using the configured ChallengeFactory, and returns a CBOR-encoded DirectValidationResult
// indicating whether the client-provided OTP is valid.
type DirectEndpoint struct {
	factory ChallengeFactory
}

// NewDirectEndpoint constructs a new DirectEndpoint with the given factory.
// Returns an error if factory is nil or fails its optional Check() validation.
func NewDirectEndpoint(factory ChallengeFactory) (*DirectEndpoint, error) {
	if factory == nil {
		return nil, wrapError(ErrValidation, "nil factory")
	}

	// validate factory if it implements Checker
	if fc, ok := factory.(interface{ Check() error }); ok {
		if err := fc.Check(); err != nil {
			return nil, wrapError(err, "failed factory validation")
		}
	}

	return &DirectEndpoint{
		factory: factory,
	}, nil
}

// ServeHTTP handles incoming POST requests carrying a CBOR-encoded DirectLoginRequest.
// It enforces the POST method, decodes the request, derives the expected OTP server-side,
// compares it against the client-provided OTP using constant-time comparison,
// and returns a CBOR-encoded DirectValidationResult.
func (self *DirectEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce POST method
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Read the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxSlpDirectRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 3. Unmarshal CBOR payload into DirectLoginRequest
	// ctapSrz.Unmarshal calls dlr.Check() automatically.
	var dlr DirectLoginRequest
	if err := ctapSrz.Unmarshal(body, &dlr); err != nil {
		http.Error(w, "failed to decode cbor request", http.StatusBadRequest)
		return
	}

	// 4. transform dlr in CardChalResponse
	osz := len(dlr.Otp) // osz > 0 enforced by dlr.Check
	cr := CardChalResponse{
		SessionId: dlr.SessionId,
		CardId:    dlr.CardId,
		SyncHint:  dlr.Otp[osz-1],
		E:         dlr.E,
	}

	// 5. calculate the expected otp
	otp, err := self.factory.GetServerOtp(&cr, nil)
	if nil != err {
		http.Error(w, "failed otp calculation", http.StatusBadRequest)
	}

	// 6. compare calculated otp with received one
	res := DirectValidationResult{
		Valid: (subtle.ConstantTimeCompare(otp, dlr.Otp) == 1),
	}

	// 7. Marshal the response to CBOR
	data, err := ctapSrz.Marshal(&res)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	// 8. Return the response
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// DirectCheckOtp submits a DirectLoginRequest to the given directLoginUrl and returns
// whether the server validated the client OTP. It uses the provided HttpClient to
// execute the request, allowing callers to control transport, timeouts, and testability.
// The caller is responsible for enforcing deadlines via the context.
// Returns an error if the request cannot be sent, the response is non-2xx,
// or the response body cannot be decoded.
func DirectCheckOtp(ctx context.Context, client HttpClient, directLoginUrl string, dlr *DirectLoginRequest) (status bool, err error) {

	// marshal dlr to CBOR
	srzdlr, err := ctapSrz.Marshal(dlr)
	if nil != err {
		return status, wrapError(err, "failed to marshal dlr")
	}
	buf := bytes.NewBuffer(srzdlr)

	// create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", directLoginUrl, buf)
	if err != nil {
		return status, wrapError(err, "failed to create request")
	}

	// Set Accept header for CBOR
	req.Header.Set("Accept", "application/cbor")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return status, wrapError(err, "failed to execute request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return status, wrapError(ErrHttpStatus, "invalid Http resp status %d", resp.StatusCode)
	}

	// decode CBOR response
	var dvr DirectValidationResult
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return status, wrapError(err, "failed to read response body")
	}
	err = ctapSrz.Unmarshal(body, &dvr)
	if err != nil {
		return status, wrapError(err, "failed to unmarshal CBOR resp")
	}
	status = dvr.Valid

	return status, nil
}

// HttpClient is a minimal interface for executing HTTP requests.
// It is satisfied by *http.Client, allowing callers to inject
// a custom or mock implementation for testing.
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DirectLoginRequest is the client-to-server payload for the SlpDirect authentication protocol.
// It carries the session reference, card identity, client-generated OTP, and optionally
// a client ephemeral key for schemes using E2S2 key exchange.
// The last byte of Otp encodes the synchronization hint used by the server to align OTP time windows.
type DirectLoginRequest struct {
	SessionId []byte                      `json:"sid" cbor:"1,keyasint"`
	CardId    []byte                      `json:"cid" cbor:"2,keyasint"`
	Otp       []byte                      `json:"otp" cbor:"3,keyasint"`
	E         credentials.PublicKeyHandle `json:"e,omitzero" cbor:"4,keyasint,omitzero"`
}

// Check validates the DirectLoginRequest and returns an error if any required field is missing.
func (self *DirectLoginRequest) Check() error {
	if nil == self {
		return wrapError(ErrValidation, "nil DirectLoginRequest")
	}
	if 0 == len(self.SessionId) {
		return wrapError(ErrValidation, "empty SessionId")
	}
	if 0 == len(self.CardId) {
		return wrapError(ErrValidation, "empty CardId")
	}
	if 0 == len(self.Otp) {
		return wrapError(ErrValidation, "empty Otp")
	}

	return nil

}

// DirectValidationResult holds the outcome of an SlpDirect OTP validation.
type DirectValidationResult struct {
	Valid bool `json:"valid" cbor:"1,keyasint"`
}
