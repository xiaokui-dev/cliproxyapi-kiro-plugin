package kiro

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

func TestKiroModelsForAuthDiscoversAvailableModels(t *testing.T) {
	storage, errMarshal := json.Marshal(kiroCredential{
		AccessToken: "test-access-token",
		Region:      "eu-west-1",
		ProfileArn:  "arn:aws:codewhisperer:eu-west-1:123:profile/test",
	})
	if errMarshal != nil {
		t.Fatalf("marshal credential: %v", errMarshal)
	}
	rawRequest, errMarshal := json.Marshal(authModelRequest{
		AuthModelRequest: pluginapi.AuthModelRequest{StorageJSON: storage},
		HostCallbackID:   "callback-123",
	})
	if errMarshal != nil {
		t.Fatalf("marshal auth model request: %v", errMarshal)
	}

	var gotRequest hostapi.HTTPRequest
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		gotRequest = req
		return &hostapi.HTTPResponse{
			StatusCode: 200,
			Body: []byte(`{
				"defaultModel":{"modelId":"auto"},
				"models":[
					{"modelId":"claude-sonnet-4.6","modelName":"Claude Sonnet 4.6","description":"1M context","supportedInputTypes":["TEXT","IMAGE","text"],"tokenLimits":{"maxInputTokens":1000000,"maxOutputTokens":64000}},
					{"modelId":"auto","modelName":"Auto","supportedInputTypes":["TEXT","IMAGE"],"tokenLimits":{"maxInputTokens":1000000,"maxOutputTokens":64000}},
					{"modelId":"qwen3-coder-next","modelName":"Qwen3 Coder Next","supportedInputTypes":["TEXT","IMAGE","IMAGE"]},
					{"modelId":""}
				]
			}`),
		}, nil
	}

	rawResponse, errHandle := kiroModelsForAuth(rawRequest)
	if errHandle != nil {
		t.Fatalf("model discovery failed: %v", errHandle)
	}
	if gotRequest.HostCallbackID != "callback-123" {
		t.Fatalf("expected callback ID callback-123, got %q", gotRequest.HostCallbackID)
	}
	if gotRequest.Method != "POST" {
		t.Fatalf("expected POST, got %q", gotRequest.Method)
	}
	if gotRequest.URL != "https://management.eu-west-1.kiro.dev/" {
		t.Fatalf("unexpected URL: %q", gotRequest.URL)
	}
	if got := gotRequest.Headers["Authorization"]; len(got) != 1 || got[0] != "Bearer test-access-token" {
		t.Fatalf("unexpected authorization header: %#v", got)
	}
	if got := gotRequest.Headers["Content-Type"]; len(got) != 1 || got[0] != "application/x-amz-json-1.0" {
		t.Fatalf("unexpected content type: %#v", got)
	}
	if got := gotRequest.Headers["x-amz-target"]; len(got) != 1 || got[0] != listAvailableModelsTarget {
		t.Fatalf("unexpected target header: %#v", got)
	}
	if got := gotRequest.Headers["TokenType"]; len(got) != 1 || got[0] != "SSO_OIDC" {
		t.Fatalf("unexpected token type header: %#v", got)
	}

	var body listAvailableModelsRequest
	if errUnmarshal := json.Unmarshal(gotRequest.Body, &body); errUnmarshal != nil {
		t.Fatalf("decode upstream request: %v", errUnmarshal)
	}
	if body.Origin != originAIEditor || body.ProfileArn != "arn:aws:codewhisperer:eu-west-1:123:profile/test" {
		t.Fatalf("unexpected upstream request body: %+v", body)
	}

	var envelope wire.Envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &envelope); errUnmarshal != nil {
		t.Fatalf("decode plugin envelope: %v", errUnmarshal)
	}
	if !envelope.OK {
		t.Fatalf("unexpected error envelope: %s", rawResponse)
	}
	var result pluginapi.ModelResponse
	if errUnmarshal := json.Unmarshal(envelope.Result, &result); errUnmarshal != nil {
		t.Fatalf("decode model response: %v", errUnmarshal)
	}
	if result.Provider != providerKiro || len(result.Models) != 3 {
		t.Fatalf("unexpected model response: provider=%q models=%d", result.Provider, len(result.Models))
	}

	sonnet := result.Models[0]
	if sonnet.ID != "claude-sonnet-4-6" || sonnet.Name != "claude-sonnet-4.6" {
		t.Fatalf("unexpected Claude IDs: ID=%q Name=%q", sonnet.ID, sonnet.Name)
	}
	if sonnet.DisplayName != "Claude Sonnet 4.6" || sonnet.Description != "1M context" {
		t.Fatalf("unexpected Claude labels: %+v", sonnet)
	}
	if sonnet.InputTokenLimit != 1000000 || sonnet.OutputTokenLimit != 64000 ||
		sonnet.ContextLength != 1000000 || sonnet.MaxCompletionTokens != 64000 {
		t.Fatalf("unexpected Claude limits: %+v", sonnet)
	}
	if got, want := strings.Join(sonnet.SupportedInputModalities, ","), "text,image"; got != want {
		t.Fatalf("unexpected Claude modalities: %q", got)
	}

	if result.Models[1].ID != "auto" || result.Models[1].Name != "auto" {
		t.Fatalf("unexpected auto model: %+v", result.Models[1])
	}
	qwen := result.Models[2]
	if qwen.ID != "qwen3-coder-next" || qwen.InputTokenLimit != defaultModelInputTokenLimit ||
		qwen.OutputTokenLimit != defaultModelOutputTokenLimit {
		t.Fatalf("unexpected Qwen fallback metadata: %+v", qwen)
	}
}

func TestKiroModelsForAuthReturnsDiscoveryErrors(t *testing.T) {
	tests := []struct {
		name       string
		storage    string
		status     int
		body       string
		wantCode   string
		wantStatus int
		callHTTP   bool
	}{
		{
			name:       "invalid storage JSON",
			storage:    "{",
			wantCode:   "invalid_credential",
			wantStatus: 400,
		},
		{
			name:       "missing access token",
			storage:    `{"profileArn":"arn:test"}`,
			wantCode:   "invalid_credential",
			wantStatus: 400,
		},
		{
			name:       "upstream status",
			storage:    `{"accessToken":"test-token"}`,
			status:     403,
			body:       "bearer token invalid",
			wantCode:   "upstream_status",
			wantStatus: 403,
			callHTTP:   true,
		},
		{
			name:       "invalid response JSON",
			storage:    `{"accessToken":"test-token"}`,
			status:     200,
			body:       "not-json",
			wantCode:   "upstream_error",
			wantStatus: 502,
			callHTTP:   true,
		},
		{
			name:       "empty model list",
			storage:    `{"accessToken":"test-token"}`,
			status:     200,
			body:       `{"models":[]}`,
			wantCode:   "upstream_error",
			wantStatus: 502,
			callHTTP:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldHTTPDo := kiroHTTPDo
			t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
			called := false
			kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
				called = true
				return &hostapi.HTTPResponse{StatusCode: tt.status, Body: []byte(tt.body)}, nil
			}

			rawRequest, errMarshal := json.Marshal(authModelRequest{
				AuthModelRequest: pluginapi.AuthModelRequest{StorageJSON: []byte(tt.storage)},
			})
			if errMarshal != nil {
				t.Fatalf("marshal request: %v", errMarshal)
			}
			rawResponse, errHandle := kiroModelsForAuth(rawRequest)
			if errHandle != nil {
				t.Fatalf("unexpected handler error: %v", errHandle)
			}
			if called != tt.callHTTP {
				t.Fatalf("HTTP called=%v, want %v", called, tt.callHTTP)
			}

			var envelope wire.Envelope
			if errUnmarshal := json.Unmarshal(rawResponse, &envelope); errUnmarshal != nil {
				t.Fatalf("decode envelope: %v", errUnmarshal)
			}
			if envelope.OK || envelope.Error == nil {
				t.Fatalf("expected error envelope: %s", rawResponse)
			}
			if envelope.Error.Code != tt.wantCode || envelope.Error.HTTPStatus != tt.wantStatus {
				t.Fatalf("unexpected error: %+v", envelope.Error)
			}
		})
	}
}

func TestClientKiroModelID(t *testing.T) {
	tests := map[string]string{
		"claude-opus-4.8":   "claude-opus-4-8",
		"claude-sonnet-4.6": "claude-sonnet-4-6",
		"claude-sonnet-4":   "claude-sonnet-4",
		"auto":              "auto",
		"deepseek-3.2":      "deepseek-3.2",
	}
	for native, want := range tests {
		if got := clientKiroModelID(native); got != want {
			t.Errorf("clientKiroModelID(%q) = %q, want %q", native, got, want)
		}
	}
}
