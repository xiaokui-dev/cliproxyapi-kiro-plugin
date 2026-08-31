package kiro

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
)

// decodeLoginStart unwraps a startKiroLogin envelope into the login response.
func decodeLoginStart(t *testing.T, raw []byte) pluginapi.AuthLoginStartResponse {
	t.Helper()
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}
	var resp pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode login start response: %v", err)
	}
	return resp
}

// decodeLoginPoll unwraps a pollKiroLogin envelope into the poll response.
func decodeLoginPoll(t *testing.T, raw []byte) pluginapi.AuthLoginPollResponse {
	t.Helper()
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}
	var resp pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode login poll response: %v", err)
	}
	return resp
}

// resetKiroConfig clears the global plugin config so config-driven tests do not
// leak state into each other.
func resetKiroConfig(t *testing.T) {
	t.Helper()
	config.Apply(mustConfigRequest(t, ""))
	t.Cleanup(func() { config.Apply(mustConfigRequest(t, "")) })
}

func TestStartKiroLoginDeviceFlow(t *testing.T) {
	resetKiroConfig(t)
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var deviceAuthBody string
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		switch {
		case strings.HasSuffix(req.URL, "/client/register"):
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"clientId":"cid","clientSecret":"secret"}`)}, nil
		case strings.HasSuffix(req.URL, "/device_authorization"):
			deviceAuthBody = string(req.Body)
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"deviceCode":"dev-123","userCode":"WXYZ","verificationUri":"https://d.example/","verificationUriComplete":"https://d.example/?code=WXYZ","expiresIn":600,"interval":5}`)}, nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL)
			return nil, nil
		}
	}

	raw, err := startKiroLogin([]byte(`{"Provider":"kiro","host_callback_id":"cb-1"}`))
	if err != nil {
		t.Fatalf("startKiroLogin: %v", err)
	}
	resp := decodeLoginStart(t, raw)

	if resp.URL != "https://d.example/?code=WXYZ" {
		t.Fatalf("unexpected verification URL: %q", resp.URL)
	}
	if !strings.HasPrefix(resp.State, "kiro-") {
		t.Fatalf("unexpected state: %q", resp.State)
	}
	if metaString(resp.Metadata, "clientId") != "cid" ||
		metaString(resp.Metadata, "clientSecret") != "secret" ||
		metaString(resp.Metadata, "deviceCode") != "dev-123" ||
		metaString(resp.Metadata, "region") != defaultKiroRegion ||
		metaString(resp.Metadata, "authMethod") != builderIDAuthMethod {
		t.Fatalf("device-code context not carried in metadata: %+v", resp.Metadata)
	}
	if !strings.Contains(deviceAuthBody, builderIDStartURL) {
		t.Fatalf("Builder ID device auth should use default startUrl, body=%s", deviceAuthBody)
	}
	if resp.ExpiresAt.IsZero() {
		t.Fatalf("expected non-zero ExpiresAt")
	}
}

func TestStartKiroLoginOrgIdC(t *testing.T) {
	resetKiroConfig(t)
	config.Apply(mustConfigRequest(t, "enabled: true\nstart_url: https://d-9067abc.awsapps.com/start\nidc_region: eu-west-1\n"))

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var deviceAuthBody, registerURL string
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		switch {
		case strings.HasSuffix(req.URL, "/client/register"):
			registerURL = req.URL
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"clientId":"cid","clientSecret":"secret"}`)}, nil
		case strings.HasSuffix(req.URL, "/device_authorization"):
			deviceAuthBody = string(req.Body)
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"deviceCode":"dev-9","verificationUriComplete":"https://d-9067abc.awsapps.com/start/#/device?user_code=AAAA","expiresIn":600,"interval":5}`)}, nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL)
			return nil, nil
		}
	}

	raw, err := startKiroLogin([]byte(`{"Provider":"kiro","host_callback_id":"cb-1"}`))
	if err != nil {
		t.Fatalf("startKiroLogin: %v", err)
	}
	resp := decodeLoginStart(t, raw)

	if metaString(resp.Metadata, "authMethod") != idcAuthMethod {
		t.Fatalf("org login should use IdC auth method: %+v", resp.Metadata)
	}
	if metaString(resp.Metadata, "region") != "eu-west-1" {
		t.Fatalf("org login should use idc_region, got %q", metaString(resp.Metadata, "region"))
	}
	if !strings.Contains(registerURL, "oidc.eu-west-1.amazonaws.com") {
		t.Fatalf("org login should hit idc_region OIDC endpoint, got %q", registerURL)
	}
	if !strings.Contains(deviceAuthBody, "https://d-9067abc.awsapps.com/start") {
		t.Fatalf("org device auth should carry org startUrl, body=%s", deviceAuthBody)
	}
}

// decodeLoginStartError expects an error envelope and returns its code.
func decodeLoginStartError(t *testing.T, raw []byte) string {
	t.Helper()
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK || env.Error == nil {
		t.Fatalf("expected error envelope, got: %s", string(raw))
	}
	return env.Error.Code
}

func TestStartKiroLoginExplicitBuilderID(t *testing.T) {
	resetKiroConfig(t)
	// An explicit Builder ID choice must ignore a leftover start_url and use the
	// default Builder ID portal.
	config.Apply(mustConfigRequest(t, "login_method: AWS Builder ID\nstart_url: https://d-9067abc.awsapps.com/start\n"))

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var deviceAuthBody string
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		switch {
		case strings.HasSuffix(req.URL, "/client/register"):
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"clientId":"cid","clientSecret":"secret"}`)}, nil
		case strings.HasSuffix(req.URL, "/device_authorization"):
			deviceAuthBody = string(req.Body)
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"deviceCode":"dev-1","verificationUriComplete":"https://d.example/","expiresIn":600,"interval":5}`)}, nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL)
			return nil, nil
		}
	}

	resp := decodeLoginStart(t, mustStart(t))
	if metaString(resp.Metadata, "authMethod") != builderIDAuthMethod {
		t.Fatalf("explicit Builder ID should use builder-id auth method: %+v", resp.Metadata)
	}
	if !strings.Contains(deviceAuthBody, builderIDStartURL) {
		t.Fatalf("explicit Builder ID should use default startUrl, body=%s", deviceAuthBody)
	}
}

func TestStartKiroLoginIDCMissingStartURL(t *testing.T) {
	resetKiroConfig(t)
	config.Apply(mustConfigRequest(t, "login_method: IDC\n"))

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		t.Fatalf("IDC without start_url must not perform any HTTP call, got %s", req.URL)
		return nil, nil
	}

	if code := decodeLoginStartError(t, mustStart(t)); code != "login_config_missing" {
		t.Fatalf("expected login_config_missing, got %q", code)
	}
}

func TestStartKiroLoginSocialUnsupported(t *testing.T) {
	for _, method := range []string{"Google", "GitHub"} {
		t.Run(method, func(t *testing.T) {
			resetKiroConfig(t)
			config.Apply(mustConfigRequest(t, "login_method: "+method+"\n"))

			oldHTTPDo := kiroHTTPDo
			t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
			kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
				t.Fatalf("social login must not perform any HTTP call, got %s", req.URL)
				return nil, nil
			}

			if code := decodeLoginStartError(t, mustStart(t)); code != "login_unsupported" {
				t.Fatalf("expected login_unsupported, got %q", code)
			}
		})
	}
}

func mustStart(t *testing.T) []byte {
	t.Helper()
	raw, err := startKiroLogin([]byte(`{"Provider":"kiro","host_callback_id":"cb-1"}`))
	if err != nil {
		t.Fatalf("startKiroLogin: %v", err)
	}
	return raw
}

func mustConfigRequest(t *testing.T, configYAML string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"config_yaml": []byte(configYAML)})
	if err != nil {
		t.Fatalf("marshal config request: %v", err)
	}
	return raw
}

func TestPollKiroLoginPending(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		return &hostapi.HTTPResponse{StatusCode: 400, Body: []byte(`{"error":"authorization_pending"}`)}, nil
	}

	req := mustMarshalPollRequest(t, map[string]any{
		"clientId": "cid", "clientSecret": "secret", "deviceCode": "dev-123", "region": "us-east-1",
	})
	resp := decodeLoginPoll(t, mustPoll(t, req))
	if resp.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("expected pending, got %q (%s)", resp.Status, resp.Message)
	}
}

func TestPollKiroLoginSuccess(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"accessToken":"AT","refreshToken":"RT","expiresIn":3600}`)}, nil
	}

	req := mustMarshalPollRequest(t, map[string]any{
		"clientId": "cid", "clientSecret": "secret", "deviceCode": "dev-123", "region": "us-east-1",
	})
	resp := decodeLoginPoll(t, mustPoll(t, req))
	if resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("expected success, got %q (%s)", resp.Status, resp.Message)
	}
	if resp.Auth.Provider != providerKiro || resp.Auth.FileName == "" {
		t.Fatalf("unexpected auth data: %+v", resp.Auth)
	}
	if resp.Auth.NextRefreshAfter.IsZero() {
		t.Fatalf("expected NextRefreshAfter to be set")
	}
	var cred kiroCredential
	if err := json.Unmarshal(resp.Auth.StorageJSON, &cred); err != nil {
		t.Fatalf("decode stored credential: %v", err)
	}
	if cred.AccessToken != "AT" || cred.RefreshToken != "RT" ||
		cred.AuthMethod != builderIDAuthMethod || cred.ClientID != "cid" || cred.Region != "us-east-1" {
		t.Fatalf("stored credential incomplete: %+v", cred)
	}
	if metaString(resp.Auth.Metadata, "refresh_interval_seconds") != "" {
		// refresh_interval_seconds is numeric; just ensure the key exists.
	}
	if _, ok := resp.Auth.Metadata["refresh_interval_seconds"]; !ok {
		t.Fatalf("metadata missing refresh_interval_seconds: %+v", resp.Auth.Metadata)
	}
}

func TestPollKiroLoginMissingContext(t *testing.T) {
	req := mustMarshalPollRequest(t, map[string]any{"region": "us-east-1"})
	resp := decodeLoginPoll(t, mustPoll(t, req))
	if resp.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("expected error for missing context, got %q", resp.Status)
	}
}

func mustMarshalPollRequest(t *testing.T, metadata map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Provider":         providerKiro,
		"State":            "kiro-abc",
		"Metadata":         metadata,
		"host_callback_id": "cb-1",
	})
	if err != nil {
		t.Fatalf("marshal poll request: %v", err)
	}
	return raw
}

func mustPoll(t *testing.T, req []byte) []byte {
	t.Helper()
	raw, err := pollKiroLogin(req)
	if err != nil {
		t.Fatalf("pollKiroLogin: %v", err)
	}
	return raw
}
