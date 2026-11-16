// Package server exposes document verification over HTTP (CLI_SPEC 3.6).
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	"mdsig.dev/mdsig"
)

const (
	APIVersion             = "v1"
	DefaultMaxBodyBytes    = 4 << 20
	DefaultMaxConcurrent   = 8
	DefaultRequestTimeout  = 60 * time.Second
	maxSigBytes            = 64 << 10
	corsPreflightMaxAgeSec = "600"
)

type Options struct {
	// Version is reported by /v1/health
	Version string
	// AllowOrigins lists the web origins that may call the API from a browser ("https://example.org").
	// A request that carries any other Origin is refused; requests without Origin (servers, curl) are not.
	AllowOrigins []string

	Offline        bool
	FetchResources bool
	NoRevocation   bool
	Keyserver      string
	TSA            mdsig.TSAVerifyOptions
	Resolvers      map[string]mdsig.Resolver
	// HTTPClient is used for every outbound fetch; nil means mdsig.SafeHTTPClient, which refuses private addresses
	HTTPClient *http.Client

	MaxBodyBytes   int64
	MaxConcurrent  int
	RequestTimeout time.Duration
	Now            func() time.Time
}

type verifyRequest struct {
	Document *string `json:"document"`
}

type tsaRequest struct {
	Token *string `json:"tsa_token"`
	Sig   *string `json:"sig"`
}

type errorBody struct {
	Error string `json:"error"`
}

type handler struct {
	o    Options
	slot chan struct{}
}

// NewHandler serves POST /v1/verify, POST /v1/tsa and GET /v1/health
func NewHandler(o Options) http.Handler {
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = DefaultMaxConcurrent
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.HTTPClient == nil {
		o.HTTPClient = mdsig.SafeHTTPClient(30 * time.Second)
	}
	return &handler{o: o, slot: make(chan struct{}, o.MaxConcurrent)}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Origin")
	// a page on another origin must not drive this server, even when it cannot read the answer
	if origin := r.Header.Get("Origin"); origin != "" {
		if !slices.Contains(h.o.AllowOrigins, origin) {
			fail(w, http.StatusForbidden, "origin not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", corsPreflightMaxAgeSec)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.URL.Path {
	case "/" + APIVersion + "/health":
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "use GET")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"name": "mdsig", "version": h.o.Version, "api": APIVersion})
	case "/" + APIVersion + "/verify":
		h.post(w, r, h.verify)
	case "/" + APIVersion + "/tsa":
		h.post(w, r, h.tsa)
	default:
		fail(w, http.StatusNotFound, "not found")
	}
}

func (h *handler) post(w http.ResponseWriter, r *http.Request, run func(ctx context.Context, body []byte) (any, error)) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	// application/json is not a "simple" content type, so a browser must pass the CORS preflight first
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.o.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		fail(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	select {
	case h.slot <- struct{}{}:
		defer func() { <-h.slot }()
	default:
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.o.RequestTimeout)
	defer cancel()
	out, err := run(ctx, body)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) verify(ctx context.Context, body []byte) (any, error) {
	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Document == nil {
		return nil, errors.New(`body must be {"document": "<text>"}`)
	}
	if !utf8.ValidString(*req.Document) {
		return nil, errors.New("document is not valid UTF-8")
	}
	vo := &mdsig.VerifyOptions{
		ResolveOptions: mdsig.ResolveOptions{
			// no key store and no local keyring: a request must not read or change state on this machine
			Offline: h.o.Offline, TofuStore: &mdsig.MemoryTofuStore{}, HTTPClient: h.o.HTTPClient,
			PGPClient: h.o.HTTPClient, Keyserver: h.o.Keyserver,
		},
		ResourceCheckOptions: mdsig.ResourceCheckOptions{
			FetchResources: h.o.FetchResources && !h.o.Offline,
			FetchClient:    h.o.HTTPClient,
		},
		Resolvers:    h.o.Resolvers,
		TSA:          h.o.TSA,
		NoRevocation: h.o.NoRevocation,
	}
	if h.o.Now != nil {
		vo.Now = h.o.Now()
	}
	return mdsig.ToJSON(mdsig.VerifyDocument(ctx, *req.Document, vo)), nil
}

func (h *handler) tsa(_ context.Context, body []byte) (any, error) {
	var req tsaRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Token == nil || req.Sig == nil {
		return nil, errors.New(`body must be {"tsa_token": "<value>", "sig": "<base64>"}`)
	}
	sig, err := base64.StdEncoding.DecodeString(*req.Sig)
	if err != nil || len(sig) == 0 || len(sig) > maxSigBytes {
		return nil, errors.New("sig must be the base64 of the signature bytes")
	}
	return mdsig.ToJSONTSA(mdsig.CheckTSAToken(mdsig.UnfoldBinary(*req.Token), sig, &h.o.TSA)), nil
}
