package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

type tokenRoundtripper struct {
	cfg       Config
	secretKey paseto.V4SymmetricKey
}

type tokenResponse struct {
	Token     string    `json:"token"`      // matches "token" in the JSON
	ExpiresIn uint      `json:"expires_in"` // matches "expires_in" in the JSON
	IssuedAt  time.Time `json:"issued_at"`  // matches "issued_at" in the JSON
}

// // tokenProxyHandler proxies the token requests to the upstream token endpoints;
// // it adjusts the ?scope= parameter in the query from "repository:foo:..." to
// // "repository:repoPrefix/foo:.." and reverse proxies the query to the specified
// // tokenEndpoint.
// func tokenProxyHandler(config Config, tokenEndpoints map[string]string) http.HandlerFunc {
// 	// https://distribution.github.io/distribution/spec/auth/scope/
// 	// tokenProxyHandler: rewrote url:/_token?scope=repository%3Asnakeeyes%3Apull&service=registry.docker.io
// 	//                           into:https://auth.docker.io/token?scope=repository%3Abackplane%2Fsnakeeyes%3Apull&service=registry.docker.io
// 	// tokenProxyHandler: rewrote url:/_token?scope=repository%3Asnakeeyes%3Apull&service=registry.docker.io into:https://auth.docker.io/token?scope=repository%3Abackplane%2Fsnakeeyes%3Apull&service=registry.docker.io
// 	// tokenProxyHandler: rewrote url:/_token?scope=repository%3Apwgen%3Apull&service=registry.docker.io into:https://auth.docker.io/token?scope=repository%3Abackplane%2Fpwgen%3Apull&service=registry.docker.io
// 	// tokenProxyHandler: rewrote url:/_token?scope=repository%3Apwgen%3Apull&service=registry.docker.io into:https://auth.docker.io/token?scope=repository%3Abackplane%2Fpwgen%3Apull&service=registry.docker.io
// 	return (&httputil.ReverseProxy{
// 		FlushInterval: -1,
// 		Director: ,
// 	}).ServeHTTP
// }

// tokenProxy handles some things
func tokenProxy(cfg Config, secretKey paseto.V4SymmetricKey) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteTokenURL(cfg),
		Transport: &tokenRoundtripper{
			cfg:       cfg,
			secretKey: secretKey,
		},
	}).ServeHTTP
}

// rewriteTokenURL accepts requests at the local token endpoint and returns a
// re-written request to the upstream token service
func rewriteTokenURL(cfg Config) func(*http.Request) {
	return func(r *http.Request) {
		originalURL := r.URL.String()

		queryParams := r.URL.Query()
		serviceParam := queryParams.Get("service")
		if serviceParam == "" {
			log.Printf("rewriteTokenURL: no service parameter was found in the request: %s", originalURL)
			return
		}
		scopeParam := queryParams.Get("scope")
		if scopeParam == "" {
			log.Printf("rewriteTokenURL: no scope parameter was found in the request: %s", originalURL)
			return
		}
		originalScope, err := ParseResourceScope(scopeParam)
		if err != nil {
			log.Printf("rewriteTokenURL: unable to parse request scope parameter, error: %s; url: %s", err, originalURL)
			return
		}

		// we need to identify which of the config.ProxyItem members best matches
		// the value in the orignalScope
		proxy, err := cfg.BestMatch(originalScope)
		if err != nil {
			log.Printf("rewriteTokenURL: unable to match scope %s to a known proxy config, error: %s", scopeParam, err)
			return
		}

		// update the host and set the service param
		queryParams.Set("service", tokenEndpoints[proxy.RegistryHost].Service) // e.g. registry.docker.io

		newScope, err := ParseResourceScope(scopeParam)
		if err != nil {
			panic("unable to parse scope param a second time, this shouldn't happen")
		}
		newScope.ResourceName = fmt.Sprintf("%s/%s", proxy.RemotePrefix, strings.TrimPrefix(newScope.ResourceName, proxy.LocalPrefix))
		queryParams.Set("scope", newScope.String())
		log.Printf("tokenProxyHandler rewrote scope in request from: \"%s\" to: \"%s\"", originalScope, newScope)

		// change the request from a request to our token endpoint to the remote token endpoint
		u, _ := url.Parse(tokenEndpoints[proxy.RegistryHost].Realm) // e.g. https://auth.docker.io/token
		u.RawQuery = queryParams.Encode()
		r.Host = u.Host
		r.URL = u
		r.RequestURI = "" // clearing this to avoid conflicts

		// add the proxy config key to the request context so the transport function can use it
		r.Header.Set(proxyConfigHeader, proxy.LocalPrefix)
		log.Printf("rewriteTokenURL: rewrote url:%s into:%s", originalURL, r.URL)
	}
}

func (trt *tokenRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("tokenRoundtripper.RoundTrip: request received with url=%s", req.URL)

	// Retrieve the proxy config value from the Director
	proxyLocalPrefix := req.Header.Get(proxyConfigHeader)
	if proxyLocalPrefix == "" {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: unable to get value in proxyConfigHeader %s", proxyConfigHeader)
	}
	req.Header.Del(proxyConfigHeader)
	proxy, ok := trt.cfg.Proxies[proxyLocalPrefix]
	if !ok {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: unable to find key \"%s\" in cfg.Proxies", proxyLocalPrefix)
	}

	// at this point the docker client is requesting a token from us which can be used to download the image
	// we don't require them to authenticate to us
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		log.Printf("tokenRoundtripper.RoundTrip: WARNING received an Authorization header from the client: %s", authHeader)
	}
	req.Header.Set("Authorization", proxy.AuthHeader)

	SetUserAgent(req)
	cleanHeaders(req)

	logRequest("tokenRoundtripper.RoundTrip: about to send the following request to remote token service", req)

	// make the request to the remote
	resp, err := http.DefaultTransport.RoundTrip(req)
	logResponse("tokenRoundtripper.RoundTrip: received the following response", resp)
	if err != nil {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: upstream request failed with error: %+v", err)
	}
	log.Printf("tokenRoundtripper.RoundTrip: DEBUG upstream request completed (status=%d) url=%s", resp.StatusCode, req.URL)

	// process the response body
	responseData, err := parseTokenRequestResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: unable to parse upstream token response; err:%s", err)
	}
	log.Printf("tokenRoundtripper.RoundTrip: DEBUG parsed response data: %+v", responseData)

	if responseData.Token == "" {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: no token found in parsed response body: %+v", responseData)
	}

	// issue a token with the real upstream token embedded inside
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(responseData.IssuedAt.Add(time.Duration(responseData.ExpiresIn) * time.Second))
	token.SetString(tokenKeyUpstreamToken, responseData.Token)
	encryptedToken := token.V4Encrypt(trt.secretKey, nil)

	responseData.Token = encryptedToken

	log.Printf("tokenRoundtripper.RoundTrip: generted token with claims: %s", token.ClaimsJSON())

	if err := replaceResponseBody(resp, responseData); err != nil {
		return nil, fmt.Errorf("tokenRoundtripper.RoundTrip: unable to update the response body: %s", err)
	}

	return resp, nil
}
