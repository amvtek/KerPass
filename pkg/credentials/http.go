package credentials

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"code.kerpass.org/golang/internal/observability"
)

// urlEncoding is a base64.URLEncoding configured without padding.
// It is used for encoding and decoding realm identifiers in URLs.
var urlEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// RealmInfoHandler is an HTTP handler that serves realm information in CBOR format.
// It retrieves realm data from a ServerCredStore and serializes it for HTTP delivery.
type RealmInfoHandler struct {
	credStore ServerCredStore
}

// NewRealmInfoHandler creates a new RealmInfoHandler with the provided ServerCredStore.
// It returns an error if credStore is nil.
func NewRealmInfoHandler(credStore ServerCredStore) (*RealmInfoHandler, error) {
	if nil == credStore {
		return nil, newError("nil credStore")
	}
	return &RealmInfoHandler{credStore}, nil
}

// ServeHTTP allows retrieving Realm information using HTTP GET.
//
// The handler must be registered with an http.ServeMux at a URL path that ends
// with "/get-realm-infos/{realmId}". This exact path segment "get-realm-infos"
// is required to guarantee interoperability with the GetRealmInfo function.
//
// Example registration pattern:
//
//	mux.Handle("GET /get-realm-infos/{realmId}", handler)
//
// The handler expects the {realmId} path segment to contain urlsafe base64
// encoding of the desired Realm identifier with a .cbor extension appended.
// Example request: GET /get-realm-infos/abc123...xyz.cbor
//
// In production environments, this endpoint will typically be served as static files
// to improve performance and scalability. For this reason, all client errors
// (invalid requests, unknown realms, etc.) return HTTP 404 status to maintain
// compatibility with static file serving.
func (self *RealmInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	var errmsg string
	log := observability.GetObservability(r.Context()).Log().With("handler", "realm-info")
	log.Info("RealmInfoHandler called")

	srzRealmId, isCbor := strings.CutSuffix(r.PathValue("realmId"), ".cbor")
	if !isCbor {
		errmsg = "invalid path, miss .cbor extension"
		http.Error(w, errmsg, http.StatusNotFound)
		log.Debug(errmsg)
		return
	}
	// precheck len(srzRealmId)
	// min realmId length is 32 bytes & we assume 128 bytes max length
	// which roughly corresponds to 40 chrs & 172 chrs (4/3 expansion)
	if len(srzRealmId) < 40 || len(srzRealmId) > 172 {
		errmsg = "invalid realmId text size"
		http.Error(w, errmsg, http.StatusNotFound)
		log.Debug(errmsg)
		return
	}

	// decode realmId
	realmId, err := urlEncoding.DecodeString(srzRealmId)
	if nil != err {
		errmsg = "failed realmId base64 decoding"
		http.Error(w, errmsg, http.StatusNotFound)
		log.Debug(errmsg)
		return
	}

	// load Realm
	dst := Realm{}
	err = self.credStore.LoadRealm(r.Context(), realmId, &dst)
	if nil != err {
		errmsg = "unknown realmId"
		http.Error(w, errmsg, http.StatusNotFound)
		log.Debug(errmsg)
		return
	}

	// serialize Realm
	srzRealm, err := cborSrz.Marshal(dst)
	if nil != err {
		errmsg = "failed cbor serialization of realm"
		http.Error(w, errmsg, http.StatusInternalServerError)
		log.Debug(errmsg)
		return
	}

	// send response
	w.Header().Add("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(srzRealm)
	if nil != err {
		errmsg = "failed delivering response"
		log.Debug(errmsg)
	}
}

// GetRealmInfo retrieves realm information from a remote authentication server.
// It makes an HTTP GET request to the specified authServerUrl, appending the
// base64-encoded realmId with .cbor extension to the path "/get-realm-infos/".
//
// The function expects the server to implement the same protocol as RealmInfoHandler,
// returning realm data in CBOR format on success or HTTP 404 if the realm is not found.
func GetRealmInfo(ctx context.Context, authServerUrl string, realmId []byte) (*Realm, error) {
	// Encode realmId to base64 URL without padding
	srzRealmId := urlEncoding.EncodeToString(realmId)

	// Build the URL - ensure proper path concatenation
	baseUrl := strings.TrimSuffix(authServerUrl, "/")
	url := fmt.Sprintf("%s/get-realm-infos/%s.cbor", baseUrl, srzRealmId)

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, wrapError(err, "failed to create request")
	}

	// Set Accept header for CBOR
	req.Header.Set("Accept", "application/cbor")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, wrapError(err, "failed to execute request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, wrapError(ErrNotFound, "realm not found, got status %d", resp.StatusCode)
	}

	// Read and decode CBOR response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, wrapError(err, "failed to read response body")
	}

	var realm Realm
	if err := cborSrz.Unmarshal(body, &realm); err != nil {
		fmt.Printf("failed CBOR decoding of %s", string(body))
		return nil, wrapError(err, "failed to unmarshal CBOR response")
	}

	return &realm, nil
}
