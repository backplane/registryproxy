/*
Copyright 2024 Backplane BV
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"aidanwoods.dev/go-paseto"
)

const (
	proxyConfigHeader     string = "X-Proxy-Config"
	tokenKeyUpstreamToken string = "upstream-token"
)

var (
	tokenEndpoints = map[string]*WWWAuthenticateData{} // mapping of registryHosts to token endpoint URLs
	logger         *slog.Logger
)

func init() {
	logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func main() {
	// load the yaml config file
	config, err := LoadConfig()
	if err != nil {
		logger.Error("config loading error", "error", err)
		os.Exit(1)
	}
	config.Log()

	// the secret key is used to process the PASETO tokens we issue to clients
	if config.SecretKey == "" {
		logger.Error("SecretKey not found in config")
		os.Exit(1)
	}
	pasetoSecretKey, err := paseto.V4SymmetricKeyFromHex(config.SecretKey)
	if err != nil {
		logger.Error("Failed to parse PASETO symmetric key", "err", err)
		os.Exit(1)
	}

	// set up http handlers for each proxy
	mux := http.NewServeMux()
	mux.Handle("/_token", NewTokenProxy(config, pasetoSecretKey))
	mux.HandleFunc("/v2/", ServeServiceDiscoveryEndpoint) // handles exactly "/v2/" (nothing under it)

	for _, proxy := range config.Proxies {
		if _, ok := tokenEndpoints[proxy.RegistryHost]; !ok {
			// if the token endpoint for the given RegistryHost isn't in
			// tokenEndpoints we look it up, then add it
			endpoint, err := DiscoverTokenEndpoint(proxy.RegistryHost)
			if err != nil {
				logger.Error("unable to discover token endpoint", "registry", proxy.RegistryHost, "error", err)
				os.Exit(1)

			}
			tokenEndpoints[proxy.RegistryHost] = endpoint
		}

		proxyPath := fmt.Sprintf("/v2/%s/", strings.Trim(proxy.LocalPrefix, "/"))
		logger.Info("setup handler", "path", proxyPath, "proxy", proxy.LocalPrefix)
		mux.Handle(proxyPath, NewRegistryProxy(proxy, pasetoSecretKey, config.ProxyFQDN))
	}

	// serve
	hostport := fmt.Sprintf("%s:%s", config.ListenAddr, config.ListenPort)
	logger.Info("listening for network connections", "addr", hostport)

	if err := http.ListenAndServe(hostport, PanicLogger(mux)); err != http.ErrServerClosed {
		logger.Error("unable to start network listener", "error", err)
		os.Exit(1)

	}

	logger.Info("server shutdown successfully")
}

// PanicLogger intends to log something when an http handler panics
func PanicLogger(next http.Handler) http.Handler {
	// Note: this needs testing/validation, the entire concept of this middleware
	// may be the result of several wrong assumptions
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("PanicLogger recovered in HTTP handler", "handler", err)
				http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}
