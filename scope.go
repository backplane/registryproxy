// Items related to working with Docker registry auth tokens
//
// The following grammar spec is reproduced from:
// https://distribution.github.io/distribution/spec/auth/scope/
//
// scope                   := resourcescope [ ' ' resourcescope ]*
// resourcescope           := resourcetype  ":" resourcename  ":" action [ ',' action ]*
// resourcetype            := resourcetypevalue [ '(' resourcetypevalue ')' ]
// resourcetypevalue       := /[a-z0-9]+/
// resourcename            := [ hostname '/' ] component [ '/' component ]*
// hostname                := hostcomponent ['.' hostcomponent]* [':' port-number]
// hostcomponent           := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
// port-number             := /[0-9]+/
// action                  := /[a-z]*/
// component               := alpha-numeric [ separator alpha-numeric ]*
// alpha-numeric           := /[a-z0-9]+/
// separator               := /[_.]|__|[-]*/
//
// See also: https://distribution.github.io/distribution/spec/auth/token/
package main

import (
	"fmt"
	"regexp"
	"strings"
)

type TokenScope struct {
	Subject  string // user associated with the token; also in jwt "sub" field
	Audience string // the resource provider (the service field); also jwt "aud" field
	Scope    []ResourceScope
}

type ResourceScope struct {
	ResourceType    string
	ResourceName    string
	ResourceActions []string
	HostName        string
	Components      string
}

// ParseResourceScope parses the given docker auth token resource scope string
// and returns a ResourceScope struct
func ParseResourceScope(scope string) (*ResourceScope, error) {
	var ScopeRegex = regexp.MustCompile(`^(?P<type>[a-z0-9]+(?:\([a-z0-9]+\))?):(?P<name>(?P<hostname>(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])*(?:\:[0-9]+)?/)?(?P<components>[a-z0-9]+(?:(?:[_.]|__|[-]*)[a-z0-9]+)?(?:/[a-z0-9]+(?:(?:[_.]|__|[-]*)[a-z0-9]+)?)*)):(?P<actions>[a-z]*(?:,[a-z]*)*)$`)
	// given the input: "repository:samalba/my-app:pull,push"
	// ...we get the following named capture groups:
	// type: repository
	// name: samalba/my-app
	// hostname: samalba/
	// components: my-app
	// actions: pull,push

	mm, matched := MatchMap(ScopeRegex, scope)
	if !matched {
		return nil, fmt.Errorf("ParseResourceScope: unable to parse scope string; string: %s", scope)
	}

	result := &ResourceScope{}
	result.ResourceType = mm["type"]
	result.ResourceName = mm["name"]
	result.HostName = strings.TrimRight(mm["hostname"], "/")
	result.Components = mm["components"]
	result.ResourceActions = strings.Split(mm["actions"], ",")

	return result, nil
}

// ToString returns the string form of the ResourceScope
func (rs *ResourceScope) String() string {
	return strings.Join(
		[]string{
			rs.ResourceType,
			rs.ResourceName,
			strings.Join(rs.ResourceActions, ","),
		},
		":",
	)
}
