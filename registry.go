package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"aidanwoods.dev/go-paseto"
)

type RegistryProxy struct {
	Config    ProxyItem
	SecretKey paseto.V4SymmetricKey
	FQDN      string
}

// NewRegistryProxy returns a reverse proxy to the specified registry.
func NewRegistryProxy(cfg ProxyItem, secretKey paseto.V4SymmetricKey, fqdn string) http.HandlerFunc {
	rp := &RegistryProxy{
		Config:    cfg,
		SecretKey: secretKey,
		FQDN:      fqdn,
	}
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rp.Director,
		Transport:     rp,
	}).ServeHTTP
}

// Director rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*
func (rp *RegistryProxy) Director(req *http.Request) {
	u := req.URL.String()
	req.Host = rp.Config.RegistryHost
	req.URL.Host = rp.Config.RegistryHost
	req.URL.Scheme = "https"

	localPath := fmt.Sprintf("/v2/%s/", strings.Trim(rp.Config.LocalPrefix, "/"))
	remotePath := fmt.Sprintf("/v2/%s/", strings.Trim(rp.Config.RemotePrefix, "/"))

	if req.URL.Path != "/v2/" {
		if strings.HasPrefix(req.URL.Path, localPath) {
			req.URL.Path = strings.Replace(req.URL.Path, localPath, remotePath, 1)
		}
	}

	req.RequestURI = "" // clearing this to avoid conflicts
	logger.Debug("RegistryProxy.Director: rewrote url",
		"from", u,
		"to", req.URL.String())
}

// RoundTrip receives the requests from the docker clients, modifies the
// requests then performs them, finally it returns the modified result to the
// client
func (rp *RegistryProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	logger.Debug("RegistryProxy.RoundTrip: request received", "url", req.URL)

	// Retrieve the proxy config context value
	proxy := rp.Config

	// replace the outgoing "Authorization: Bearer abcdeg..." header with one we embedded in the token
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		logger.Debug("RegistryProxy.RoundTrip: have auth header", "header", authHeader)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, fmt.Errorf("RegistryProxy.RoundTrip: Authorization header in unknown format: %s", authHeader)
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		parser := paseto.NewParserForValidNow()
		token, err := parser.ParseV4Local(rp.SecretKey, tokenString, []byte{})
		if err != nil {
			return nil, fmt.Errorf("RegistryProxy.RoundTrip: unable to parse token from auth header; token:%s; error:%s", tokenString, err)
		}

		upstreamToken, err := token.GetString(tokenKeyUpstreamToken)
		if err != nil {
			logger.Debug("claims found in token", "claims", token.ClaimsJSON())
			return nil, fmt.Errorf("RegistryProxy.RoundTrip: unable to parse upstreamToken string from token; error:%s", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", upstreamToken))
		logger.Debug("RegistryProxy.RoundTrip: set Authorization header", "header", req.Header.Get("Authorization"))
	}

	SetUserAgent(req, rp.FQDN)
	CleanHeaders(req)

	LogRequest("RegistryProxy.RoundTrip: about to make the following request to upstream", req)

	resp, err := http.DefaultTransport.RoundTrip(req)
	LogResponse("RegistryProxy.RoundTrip: response from upstream", resp)
	if err != nil {
		logger.Error("RegistryProxy.RoundTrip: upstream request failed", "error", err)
		return nil, err
	}
	logger.Info("RegistryProxy.RoundTrip: upstream request completed", "status", resp.StatusCode, "url", req.URL)

	// Google Artifact Registry sends a "location: /artifacts-downloads/..." URL
	// to download blobs. We don't want these routed to the proxy itself.
	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		logger.Info("RegistryProxy.RoundTrip: applying Google Artifact Registry location header")
		resp.Header.Set("location", req.URL.Scheme+"://"+req.URL.Host+locHdr)
	}

	// If the response included a WWW-Authenticate header we replace it with
	// our own adjusted header that points to our own token endpoint
	// see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
	// and: https://distribution.github.io/distribution/spec/auth/token/
	if authHeader := resp.Header.Get("www-authenticate"); authHeader != "" {
		logger.Debug("RegistryProxy.RoundTrip: have www-authenticate header", "header", authHeader)
		authHeaderFields, ok := ParseWWWAuthenticate(authHeader)
		if !ok {
			return nil, fmt.Errorf("RegistryProxy.RoundTrip: parsing WWW-Authenticate header failed; header: %s", authHeader)
		}
		logger.Debug("RegistryProxy.RoundTrip: parsed www-authenticate header", "parsed", authHeaderFields)

		authHeaderFields.Realm = fmt.Sprintf(`https://%s/_token`, rp.FQDN)
		authHeaderFields.Service = fmt.Sprintf(`https://%s`, rp.FQDN)
		headerScope, err := ParseResourceScope(authHeaderFields.Scope)
		if err != nil {
			return nil, fmt.Errorf("failed to parse scope in www-authenticate header; error:%s", err)
		}
		headerScope.ResourceName = SlashJoin(proxy.LocalPrefix, strings.TrimPrefix(headerScope.ResourceName, proxy.RemotePrefix))
		authHeaderFields.Scope = headerScope.String()

		newAuthHeader := authHeaderFields.String()
		resp.Header.Set("www-authenticate", newAuthHeader)
		logger.Debug("RegistryProxy.RoundTrip: rewrote www-authenticate header;\n  from: %s\n    to: %s", authHeader, newAuthHeader)
	}

	return resp, nil
}
