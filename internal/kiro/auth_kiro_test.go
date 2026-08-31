package kiro

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// A social credential as produced by a Kiro desktop-app Google/GitHub login and
// then imported into auths/. It has no explicit "type" field, so recognition
// relies on refreshToken + authMethod.
const socialCredentialJSON = `{
	"accessToken": "AT-social",
	"refreshToken": "RT-social",
	"profileArn": "arn:aws:codewhisperer:us-east-1:123:profile/ABC",
	"authMethod": "social",
	"region": "us-east-1",
	"expiresAt": "2999-01-01T00:00:00Z"
}`

func decodeParse(t *testing.T, raw []byte) pluginapi.AuthParseResponse {
	t.Helper()
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}
	var resp pluginapi.AuthParseResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode parse response: %v", err)
	}
	return resp
}

func TestParseSocialCredential(t *testing.T) {
	// RawJSON is a []byte field: json.Marshal base64-encodes it, and parseKiroAuth
	// base64-decodes it back — so build the request through the real struct.
	req, err := json.Marshal(pluginapi.AuthParseRequest{
		RawJSON:  []byte(socialCredentialJSON),
		FileName: "kiro-social.json",
	})
	if err != nil {
		t.Fatalf("marshal parse request: %v", err)
	}

	raw, errParse := parseKiroAuth(req)
	if errParse != nil {
		t.Fatalf("parseKiroAuth: %v", errParse)
	}
	resp := decodeParse(t, raw)

	if !resp.Handled {
		t.Fatalf("social credential should be handled")
	}
	if resp.Auth.Provider != providerKiro {
		t.Fatalf("unexpected provider: %q", resp.Auth.Provider)
	}
	if resp.Auth.Metadata["authMethod"] != "social" {
		t.Fatalf("authMethod metadata not preserved: %+v", resp.Auth.Metadata)
	}
	if resp.Auth.Metadata["refresh_interval_seconds"] == nil {
		t.Fatalf("refresh_interval_seconds missing (needed for auto-refresh scheduling)")
	}
	if resp.Auth.NextRefreshAfter.IsZero() {
		t.Fatalf("expected NextRefreshAfter derived from expiresAt")
	}
}

func TestRefreshSocialUsesAuthServiceEndpoint(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var gotURL string
	var gotBody map[string]any
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		gotURL = req.URL
		_ = json.Unmarshal(req.Body, &gotBody)
		return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"accessToken":"AT2","refreshToken":"RT2","profileArn":"arn:new","expiresIn":3600}`)}, nil
	}

	req, err := json.Marshal(authRefreshRequest{
		AuthRefreshRequest: pluginapi.AuthRefreshRequest{StorageJSON: []byte(socialCredentialJSON)},
		HostCallbackID:     "cb-1",
	})
	if err != nil {
		t.Fatalf("marshal refresh request: %v", err)
	}

	raw, errRefresh := refreshKiroAuth(req)
	if errRefresh != nil {
		t.Fatalf("refreshKiroAuth: %v", errRefresh)
	}
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}

	// Social refresh must hit the Kiro auth service /refreshToken with just the token.
	if !strings.Contains(gotURL, "auth.desktop.kiro.dev/refreshToken") {
		t.Fatalf("social refresh hit wrong endpoint: %q", gotURL)
	}
	if _, hasClientID := gotBody["clientId"]; hasClientID {
		t.Fatalf("social refresh body must not carry clientId: %+v", gotBody)
	}
	if gotBody["refreshToken"] != "RT-social" {
		t.Fatalf("social refresh body missing refreshToken: %+v", gotBody)
	}

	var resp pluginapi.AuthRefreshResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	var cred kiroCredential
	if err := json.Unmarshal(resp.Auth.StorageJSON, &cred); err != nil {
		t.Fatalf("decode refreshed credential: %v", err)
	}
	if cred.AccessToken != "AT2" || cred.RefreshToken != "RT2" || cred.ProfileArn != "arn:new" {
		t.Fatalf("refreshed credential not updated: %+v", cred)
	}
	if cred.AuthMethod != "social" {
		t.Fatalf("authMethod should stay social, got %q", cred.AuthMethod)
	}
}
