package observability

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Middleware holds configuration for HTTP Observability
type Middleware struct {
	TraceIdHeader string
}

// Wrap returns an Handler that add Observability to http Request Context and call next.
func (self Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()

		var tId string
		if "" != self.TraceIdHeader {
			tId = r.Header.Get(self.TraceIdHeader)
		}
		if "" == tId {
			tId = uuid.New().String()
		}

		log := GetObservability(r.Context()).Log().With("tId", tId)
		obs := Observability{Logger: log}
		ctx := SetObservability(r.Context(), &obs)
		sw := statusRecorder{ResponseWriter: w}
		next.ServeHTTP(&sw, r.Clone(ctx))
		log.Info(
			"processed HTTP request",
			"method", r.Method,
			"host", r.Host,
			"uri", r.RequestURI,
			"status", sw.status,
			"duration", time.Since(t0),
		)

	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (self *statusRecorder) WriteHeader(statusCode int) {
	self.status = statusCode
	self.ResponseWriter.WriteHeader(statusCode)
}

var _ http.ResponseWriter = &statusRecorder{}
