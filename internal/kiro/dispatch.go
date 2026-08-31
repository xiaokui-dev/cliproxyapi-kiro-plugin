package kiro

import (
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// HandleMethod dispatches a host RPC call to the matching handler and returns a
// JSON envelope. request is the raw JSON body of the method-specific request.
func HandleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	// ---- lifecycle ----
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		config.Apply(request)
		return wire.OK(kiroRegistration())
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		return wire.OK(map[string]any{})

	// ---- auth provider ----
	case pluginabi.MethodAuthIdentifier:
		return wire.OK(identifierResponse{Identifier: providerKiro})
	case pluginabi.MethodAuthParse:
		return parseKiroAuth(request)
	case pluginabi.MethodAuthLoginStart:
		return startKiroLogin(request)
	case pluginabi.MethodAuthLoginPoll:
		return pollKiroLogin(request)
	case pluginabi.MethodAuthRefresh:
		return refreshKiroAuth(request)

	// ---- model provider ----
	case pluginabi.MethodModelStatic:
		// Kiro models are OAuth-bound; there are no static (auth-less) models.
		return wire.OK(pluginapi.ModelResponse{Provider: providerKiro})
	case pluginabi.MethodModelForAuth:
		return kiroModelsForAuth(request)

	// ---- executor ----
	case pluginabi.MethodExecutorIdentifier:
		return wire.OK(identifierResponse{Identifier: providerKiro})
	case pluginabi.MethodExecutorExecute:
		return executeKiro(request)
	case pluginabi.MethodExecutorExecuteStream:
		return executeKiroStream(request)
	case pluginabi.MethodExecutorCountTokens,
		pluginabi.MethodExecutorHTTPRequest:
		return wire.ErrorStatus("not_implemented", "count-tokens/http-request are not implemented yet", http.StatusNotImplemented), nil

	// ---- management API ----
	case pluginabi.MethodManagementRegister:
		return registerManagement()
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)

	default:
		return wire.Error("unknown_method", "unknown method: "+method), nil
	}
}

// kiroRegistration declares the plugin metadata and capabilities.
func kiroRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             providerKiro,
			Version:          "0.1.0",
			Author:           "xiaokui-dev",
			GitHubRepository: "https://github.com/xiaokui-dev/cliproxyapi-kiro-plugin",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:       "login_method",
					Type:       pluginapi.ConfigFieldTypeEnum,
					EnumValues: []string{loginMethodBuilderID, loginMethodIDC, loginMethodGoogle, loginMethodGitHub},
					Description: "登录方式。AWS Builder ID / IDC 需先保存配置，再到「Kiro OAuth」页选择 Kiro 登录。\n" +
						"· AWS Builder ID：无需其它配置，保存即可发起设备码登录。\n" +
						"· IDC：组织 IAM Identity Center 登录，仅需填写 start_url 与 idc_region。\n" +
						"· Google / GitHub：暂不支持交互登录。请在 Kiro 桌面应用登录后导出凭据 JSON，放入宿主 auth-dir。\n" +
						"  导入 JSON 需含：accessToken、refreshToken、profileArn、authMethod(=social)、region(通常 us-east-1)；导入后插件会经 Kiro auth service 自动刷新。",
				},
				{Name: "region", Type: pluginapi.ConfigFieldTypeString, Description: "CodeWhisperer 端点使用的默认 AWS 区域（默认 us-east-1），所有登录方式通用。"},
				{Name: "start_url", Type: pluginapi.ConfigFieldTypeString, Description: "仅 IDC 需要：组织 IAM Identity Center 门户 start URL，例如 https://d-xxxx.awsapps.com/start。其它登录方式无需填写。"},
				{Name: "idc_region", Type: pluginapi.ConfigFieldTypeString, Description: "仅 IDC 需要：组织 IdC OIDC 端点所在 AWS 区域（留空则回退到 region，再回退 us-east-1）。"},
				{Name: "base_url", Type: pluginapi.ConfigFieldTypeString, Description: "可选：覆盖 generateAssistantResponse 端点 URL（一般无需填写）。"},
			},
		},
		Capabilities: registrationCapability{
			AuthProvider:          true,
			ModelProvider:         true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  []string{"claude"},
			ExecutorOutputFormats: []string{"claude"},
			ManagementAPI:         true,
		},
	}
}
