package kiro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

const (
	listAvailableModelsURLTemplate = "https://management.%s.kiro.dev/"
	listAvailableModelsTarget      = "KiroControlPlaneBearerService.ListAvailableModels"
	defaultModelInputTokenLimit    = int64(200000)
	defaultModelOutputTokenLimit   = int64(8192)
)

// kiroModelIDs are the client-facing model names retained by the legacy fixed-list
// helper for compatibility with existing callers.
var kiroModelIDs = []string{
	"claude-opus-5",
	"claude-opus-4-8",
	"claude-opus-4-7",
	"claude-opus-4-6",
	"claude-opus-4-5",
	"claude-sonnet-5",
	"claude-sonnet-4-6",
	"claude-sonnet-4-5",
	"claude-sonnet-4-0",
	"claude-haiku-4-5",
}

// modelMapping translates a client-facing model name to the CodeWhisperer-native
// model name sent upstream. It ONLY normalizes the version separator (client
// "claude-opus-4-8" -> upstream "claude-opus-4.8"); it deliberately does NOT
// collapse several versions onto one model.
//
// Per-account availability is enforced UPSTREAM: Kiro accepts or rejects each
// model (INVALID_MODEL_ID) according to the account's plan/tier. The plugin must
// not pre-assume any account's capabilities.
var modelMapping = map[string]string{
	"claude-opus-5":     "claude-opus-5",
	"claude-opus-4-8":   "claude-opus-4.8",
	"claude-opus-4-7":   "claude-opus-4.7",
	"claude-opus-4-6":   "claude-opus-4.6",
	"claude-opus-4-5":   "claude-opus-4.5",
	"claude-sonnet-5":   "claude-sonnet-5",
	"claude-sonnet-4-6": "claude-sonnet-4.6",
	"claude-sonnet-4-5": "claude-sonnet-4.5",
	"claude-sonnet-4-0": "claude-sonnet-4.0",
	"claude-haiku-4-5":  "claude-haiku-4.5",
}

// nativeModelMapping keeps the public client ID stable while preserving the
// native dotted ID returned by Kiro in ModelInfo.Name.
var nativeModelMapping = map[string]string{
	"claude-opus-5":     "claude-opus-5",
	"claude-opus-4.8":   "claude-opus-4-8",
	"claude-opus-4.7":   "claude-opus-4-7",
	"claude-opus-4.6":   "claude-opus-4-6",
	"claude-opus-4.5":   "claude-opus-4-5",
	"claude-sonnet-5":   "claude-sonnet-5",
	"claude-sonnet-4.6": "claude-sonnet-4-6",
	"claude-sonnet-4.5": "claude-sonnet-4-5",
	"claude-sonnet-4.0": "claude-sonnet-4-0",
	"claude-haiku-4.5":  "claude-haiku-4-5",
}

// resolveKiroModel returns the CodeWhisperer-native model name for a client-facing
// model ID, falling back to the input when there is no mapping (used by the executor in M3).
func resolveKiroModel(id string) string {
	if mapped, ok := modelMapping[id]; ok {
		return mapped
	}
	return id
}

// clientKiroModelID converts a native Kiro model ID to the public client ID used
// by the existing plugin API. New or non-Claude IDs remain unchanged.
func clientKiroModelID(id string) string {
	if mapped, ok := nativeModelMapping[id]; ok {
		return mapped
	}
	return id
}

// kiroModels builds the ModelInfo list advertised to the host registry. It is
// retained for static compatibility, while model.for_auth uses the account's
// management response below.
func kiroModels() []pluginapi.ModelInfo {
	models := make([]pluginapi.ModelInfo, 0, len(kiroModelIDs))
	for _, id := range kiroModelIDs {
		models = append(models, pluginapi.ModelInfo{
			ID:                         id,
			Object:                     "model",
			OwnedBy:                    providerKiro,
			Type:                       "claude",
			DisplayName:                id,
			Name:                       id,
			SupportedGenerationMethods: []string{"generateContent"},
			InputTokenLimit:            defaultModelInputTokenLimit,
			OutputTokenLimit:           defaultModelOutputTokenLimit,
			ContextLength:              defaultModelInputTokenLimit,
			MaxCompletionTokens:        defaultModelOutputTokenLimit,
		})
	}
	return models
}

// authModelRequest mirrors the host's rpcAuthModelRequest: the embedded
// AuthModelRequest plus the callback ID needed for host.http.do.
type authModelRequest struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type listAvailableModelsRequest struct {
	Origin     string `json:"origin"`
	ProfileArn string `json:"profileArn,omitempty"`
}

type listAvailableModelsResponse struct {
	Models []availableModel `json:"models"`
}

type availableModel struct {
	ModelID             string      `json:"modelId"`
	ModelName           string      `json:"modelName"`
	Description         string      `json:"description"`
	SupportedInputTypes []string    `json:"supportedInputTypes"`
	TokenLimits         tokenLimits `json:"tokenLimits"`
}

type tokenLimits struct {
	MaxInputTokens  int64 `json:"maxInputTokens"`
	MaxOutputTokens int64 `json:"maxOutputTokens"`
}

// kiroModelsForAuth asks Kiro which models the credential can actually use.
// The management endpoint is account-scoped by accessToken/profileArn, so the
// result must not be replaced with a fixed global model list.
func kiroModelsForAuth(request []byte) ([]byte, error) {
	var req authModelRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.StorageJSON, &cred); errUnmarshal != nil {
		return wire.ErrorStatus("invalid_credential", "decode kiro credential: "+errUnmarshal.Error(), http.StatusBadRequest), nil
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		return wire.ErrorStatus("invalid_credential", "kiro credential has no accessToken", http.StatusBadRequest), nil
	}

	region := firstNonEmptyStr(cred.Region, cred.IDCRegion, defaultKiroRegion)
	body, errMarshal := json.Marshal(listAvailableModelsRequest{
		Origin:     originAIEditor,
		ProfileArn: strings.TrimSpace(cred.ProfileArn),
	})
	if errMarshal != nil {
		return nil, fmt.Errorf("encode list available models request: %w", errMarshal)
	}

	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: req.HostCallbackID,
		Method:         http.MethodPost,
		URL:            fmt.Sprintf(listAvailableModelsURLTemplate, region),
		Headers:        listAvailableModelsHeaders(cred),
		Body:           body,
	})
	if errDo != nil {
		return wire.ErrorStatus("upstream_error", "list available models request: "+errDo.Error(), http.StatusBadGateway), nil
	}
	if resp == nil {
		return wire.ErrorStatus("upstream_error", "list available models returned no response", http.StatusBadGateway), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wire.ErrorStatus("upstream_status", fmt.Sprintf("ListAvailableModels HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 300)), resp.StatusCode), nil
	}

	var decoded listAvailableModelsResponse
	if errUnmarshal := json.Unmarshal(resp.Body, &decoded); errUnmarshal != nil {
		return wire.ErrorStatus("upstream_error", "decode ListAvailableModels response: "+errUnmarshal.Error(), http.StatusBadGateway), nil
	}
	models := availableModelsToPluginModels(decoded.Models)
	if len(models) == 0 {
		return wire.ErrorStatus("upstream_error", "ListAvailableModels returned no usable models", http.StatusBadGateway), nil
	}

	return wire.OK(pluginapi.ModelResponse{
		Provider: providerKiro,
		Models:   models,
	})
}

func listAvailableModelsHeaders(cred kiroCredential) map[string][]string {
	mid := machineID(cred)
	return map[string][]string{
		"Authorization":         {"Bearer " + cred.AccessToken},
		"Content-Type":          {"application/x-amz-json-1.0"},
		"Accept":                {"application/json"},
		"x-amz-target":          {listAvailableModelsTarget},
		"TokenType":             {"SSO_OIDC"},
		"amz-sdk-invocation-id": {uuidV4()},
		"amz-sdk-request":       {"attempt=1; max=3"},
		"x-amz-user-agent":      {fmt.Sprintf("aws-sdk-js/1.0.34 KiroIDE-%s-%s", kiroVersion, mid)},
		"user-agent":            {fmt.Sprintf("aws-sdk-js/1.0.34 ua/2.1 os/other lang/js md/nodejs#20.11.0 api/codewhispererstreaming#1.0.34 m/E KiroIDE-%s-%s", kiroVersion, mid)},
	}
}

func availableModelsToPluginModels(available []availableModel) []pluginapi.ModelInfo {
	models := make([]pluginapi.ModelInfo, 0, len(available))
	seen := make(map[string]struct{}, len(available))
	for _, item := range available {
		nativeID := strings.TrimSpace(item.ModelID)
		if nativeID == "" {
			continue
		}
		clientID := clientKiroModelID(nativeID)
		if _, ok := seen[clientID]; ok {
			continue
		}
		seen[clientID] = struct{}{}

		inputLimit := item.TokenLimits.MaxInputTokens
		if inputLimit <= 0 {
			inputLimit = defaultModelInputTokenLimit
		}
		outputLimit := item.TokenLimits.MaxOutputTokens
		if outputLimit <= 0 {
			outputLimit = defaultModelOutputTokenLimit
		}
		displayName := strings.TrimSpace(item.ModelName)
		if displayName == "" {
			displayName = clientID
		}

		models = append(models, pluginapi.ModelInfo{
			ID:                         clientID,
			Object:                     "model",
			OwnedBy:                    providerKiro,
			Type:                       "claude",
			DisplayName:                displayName,
			Name:                       nativeID,
			Description:                item.Description,
			SupportedGenerationMethods: []string{"generateContent"},
			InputTokenLimit:            inputLimit,
			OutputTokenLimit:           outputLimit,
			ContextLength:              inputLimit,
			MaxCompletionTokens:        outputLimit,
			SupportedInputModalities:   normalizeInputModalities(item.SupportedInputTypes),
		})
	}
	return models
}

func normalizeInputModalities(types []string) []string {
	if len(types) == 0 {
		return nil
	}
	out := make([]string, 0, len(types))
	seen := make(map[string]struct{}, len(types))
	for _, raw := range types {
		modality := strings.ToLower(strings.TrimSpace(raw))
		if modality == "" {
			continue
		}
		if _, ok := seen[modality]; ok {
			continue
		}
		seen[modality] = struct{}{}
		out = append(out, modality)
	}
	return out
}
