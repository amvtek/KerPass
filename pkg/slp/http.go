package slp

import (
	"io"
	"net/http"
)

const (
	maxCardChallengeRequestSize = 512
)

// CardChallengeEndpoint implements the http.Handler interface to process
// authentication challenge requests. It unmarshals the CBOR payload (which implicitly
// validates the request), generates a CardChallenge using the configured
// ChallengeFactory, and returns the CBOR encoded response.
type CardChallengeEndpoint struct {
	factory ChallengeFactory
}

// NewCardChallengeEndpoint constructs a new CardChallengeEndpoint.
// It requires a ChallengeFactory to generate the authentication challenges.
// If factory is nil, it returns an error.
// If factory implements a Check() method, it is called and any error is wrapped and returned.
func NewCardChallengeEndpoint(factory ChallengeFactory) (*CardChallengeEndpoint, error) {
	if factory == nil {
		return nil, wrapError(ErrValidation, "nil factory")
	}

	// Check if the concrete implementation of factory has a Check method.
	type factoryChecker interface {
		Check() error
	}
	if fc, ok := factory.(factoryChecker); ok {
		if err := fc.Check(); err != nil {
			return nil, wrapError(err, "failed factory validation")
		}
	}

	return &CardChallengeEndpoint{
		factory: factory,
	}, nil
}

// ServeHTTP handles the HTTP POST request.
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
