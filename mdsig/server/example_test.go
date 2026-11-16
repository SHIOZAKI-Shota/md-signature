package server_test

import (
	"net/http"

	"mdsig.dev/mdsig/server"
)

func ExampleNewHandler() {
	mux := http.NewServeMux()
	// the handler serves /v1/verify, /v1/tsa and /v1/health
	mux.Handle("/v1/", server.NewHandler(server.Options{
		AllowOrigins: []string{"https://app.example.com"},
	}))
	_ = mux
}
