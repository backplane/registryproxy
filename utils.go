package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

// MatchMap returns a map of named capture groups and a boolean "matched" value
func MatchMap(needle *regexp.Regexp, haystack string) (map[string]string, bool) {
	match_indexes := needle.FindStringSubmatchIndex(haystack)
	if match_indexes == nil {
		return nil, false
	}
	names := needle.SubexpNames()
	if names == nil {
		return nil, false
	}
	result := make(map[string]string)
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		idx_start := match_indexes[i*2]
		idx_end := match_indexes[(i*2)+1]
		if idx_start != -1 && idx_end != -1 { // Check if the indexes are valid
			result[name] = haystack[idx_start:idx_end]
		}
	}

	// fmt.Println("returning match map:")
	// for k, v := range result {
	// 	fmt.Printf("%s: %s\n", k, v)
	// }

	return result, true
}
func SetUserAgent(req *http.Request) bool {
	version := "0.1.0" // fixme: implement auto updates
	origHost := req.Context().Value(ctxKeyOriginalHost).(string)

	if userAgent := req.Header.Get("user-agent"); userAgent != "" {
		req.Header.Set("user-agent", fmt.Sprintf("registry-proxy/%s customDomain/%s %s", version, origHost, userAgent))
		return true
	}
	return false
}

// parseTokenRequestResponse takes an *http.Response, checks if the content type is application/json,
// and returns a map[string]string parsed from the JSON body
func parseTokenRequestResponse(resp *http.Response) (*tokenResponse, error) {
	// Check that the response Content-Type header is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		return nil, fmt.Errorf("parseTokenRequestResponse: expected content type application/json, got %s", contentType)
	}

	// Read the body of the response
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parseTokenRequestResponse: failed to read response body: %w", err)
	}

	// Unmarshal JSON data into a map
	var response tokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parseTokenRequestResponse: failed to unmarshal JSON: %w, body: %s", err, body)
	}

	return &response, nil
}

// replaceResponseBody takes an *http.Response and a map[string]string, then replaces
// the response's body with a JSON-encoded version of the map.
func replaceResponseBody(resp *http.Response, data *tokenResponse) error {
	// Marshal the map into JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Replace the body with the new JSON data
	resp.Body = io.NopCloser(bytes.NewReader(jsonData))

	// update the Content-Length header
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(jsonData)))

	// Set the Content-Type header to application/json
	resp.Header.Set("Content-Type", "application/json")

	return nil
}

type WWWAuthFields struct {
	Realm   string
	Service string
	Scope   string
	Error   string
}

// parseWWWAuthenticateHeader parses the given header contents and returns a struct
// containing the parsed values; returns a WWWAuthFields struct and a boolean OK value
func parseWWWAuthenticateHeader(headerValue string) (WWWAuthFields, bool) {
	fieldRegex := regexp.MustCompile(`(realm|service|scope|error)="([^"]+)"`)
	matches := fieldRegex.FindAllStringSubmatch(headerValue, -1)

	result := WWWAuthFields{}
	ok := false

	for _, match := range matches {
		if len(match) == 3 {
			ok = true
			switch match[1] {
			case "realm":
				result.Realm = match[2]
			case "service":
				result.Service = match[2]
			case "scope":
				result.Scope = match[2]
			case "error":
				result.Error = match[2]
			}
		}
	}

	return result, ok
}

// String returns a value useable as Www-Authenticate header
func (authFields WWWAuthFields) String() string {
	return fmt.Sprintf(`Bearer realm="%s",service="%s",scope="%s"`, authFields.Realm, authFields.Service, authFields.Scope)
}

// logRequest logs the contents of an http.Request object
func logRequest(preamble string, req *http.Request) {
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Printf("logRequest: Error dumping request: %v", err)
		return
	}
	if preamble != "" {
		preamble = preamble + ":\n"
	}
	log.Printf("%s%s", preamble, dump)
}

// logResponse logs the contents of an http.Response object
func logResponse(preamble string, resp *http.Response) {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("logResponse: Error dumping response: %v", err)
		return
	}
	if preamble != "" {
		preamble = preamble + ":\n"
	}
	log.Printf("%s%s", preamble, dump)
}

// cleanHeaders removes all headers from the request that start with "X-"
func cleanHeaders(req *http.Request) {
	for key := range req.Header {
		if strings.HasPrefix(key, "X-") && key != proxyConfigHeader {
			req.Header.Del(key)
		}
	}
}

// slashJoin joins the two given strings with a slash (ensuring exactly one slash)
func slashJoin(a, b string) string {
	return fmt.Sprintf("%s/%s", strings.TrimRight(a, "/"), strings.TrimLeft(b, "/"))
}
