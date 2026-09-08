package kiro

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// 安全边界:region 会被插进上游端点的 authority 段(如 oidc.<region>.amazonaws.com),
// 而 region 来自可被外部影响的凭据文件 / 插件配置。若不校验,形如
// "us-east-1@attacker.example/" 的取值会把请求主机改写成 attacker.example,
// 使 refreshToken / clientSecret / accessToken 被发往第三方主机。
//
// 因此本文件提供两道独立防线,两者都必须通过:
//  1. validateRegion —— 用严格格式白名单卡住 region 本身;
//  2. safeEndpoint   —— 解析拼好的最终 URL,确认 scheme/userinfo/port/host 都符合预期。
//
// 之所以用"格式白名单"而非枚举全部 AWS 区域名:枚举列表会随 AWS 开新区域而过期,
// 导致新区域用户无法使用;而下面的格式已经排除了一切能破坏 authority 的字符。

// awsRegionPattern 匹配 AWS 区域标识的规范形式:两位小写字母的地理前缀 +
// 一到多段小写字母 + 数字后缀。可覆盖 us-east-1 / ap-southeast-3 /
// us-gov-west-1 / cn-north-1 等,且不含 '@' '/' '\' ':' '?' '#' '.' 等
// 任何可改写 URL authority 的字符。
var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$`)

// maxRegionLength 为 region 长度上限,避免异常超长取值。
const maxRegionLength = 32

// validateRegion 校验 region 是否为合法 AWS 区域标识,返回清理后的取值。
// 任何不合规的输入一律拒绝,而不是"尽力清理后放行"——静默改写会掩盖攻击意图。
func validateRegion(region string) (string, error) {
	trimmed := strings.TrimSpace(region)
	if trimmed == "" {
		return "", fmt.Errorf("region is empty")
	}
	if len(trimmed) > maxRegionLength {
		return "", fmt.Errorf("region %q is too long", truncate(trimmed, maxRegionLength))
	}
	if !awsRegionPattern.MatchString(trimmed) {
		return "", fmt.Errorf("region %q is not a valid AWS region identifier", truncate(trimmed, maxRegionLength))
	}
	return trimmed, nil
}

// safeEndpoint 用已校验的 region 填充 urlTemplate,并对拼出的最终 URL 复核:
// 必须是 https、不得带 userinfo、不得指定端口、主机名必须与模板加已校验 region
// 推导出的预期主机完全一致。任一条不满足即报错。
//
// urlTemplate 必须是恰好含一个 %s 占位符的常量模板(如
// "https://oidc.%s.amazonaws.com/token"),suffix 是可选的附加路径。
func safeEndpoint(urlTemplate, region, suffix string) (string, error) {
	validRegion, errRegion := validateRegion(region)
	if errRegion != nil {
		return "", errRegion
	}

	raw := fmt.Sprintf(urlTemplate, validRegion) + suffix
	parsed, errParse := url.Parse(raw)
	if errParse != nil {
		return "", fmt.Errorf("build endpoint: %w", errParse)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("endpoint scheme must be https, got %q", parsed.Scheme)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("endpoint must not contain userinfo")
	}
	if parsed.Port() != "" {
		return "", fmt.Errorf("endpoint must not specify a port")
	}

	// 预期主机取自同一模板与同一已校验 region,因此 region 只要试图越出主机名
	// 一段(插入 '@' '/' ':' 等),实际解析出的 Hostname 就会与预期不符。
	expectedHost, errExpected := expectedHostFor(urlTemplate, validRegion)
	if errExpected != nil {
		return "", errExpected
	}
	if !strings.EqualFold(parsed.Hostname(), expectedHost) {
		return "", fmt.Errorf("endpoint host %q does not match expected host %q", parsed.Hostname(), expectedHost)
	}
	return raw, nil
}

// expectedHostFor 解析模板本身,得出填入 region 后应当出现的主机名。
func expectedHostFor(urlTemplate, validRegion string) (string, error) {
	parsed, errParse := url.Parse(fmt.Sprintf(urlTemplate, validRegion))
	if errParse != nil {
		return "", fmt.Errorf("parse endpoint template: %w", errParse)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("endpoint template has no host")
	}
	return host, nil
}

// resolveRegion 按顺序在候选取值中选出要使用的 region:
//   - 空值(字段缺省)跳过——这是合法情形,全部为空时回退 defaultKiroRegion;
//   - 首个非空取值必须合法,否则直接报错。
//
// 刻意不对"非空但非法"的取值做静默回退:凭据导入阶段已经拒收这类取值,运行时
// 若再悄悄改用别的区域,既掩盖了篡改痕迹,也会让"凭据写着 eu-west-1 却在查
// us-east-1"变成难以排查的认证失败。
func resolveRegion(candidates ...string) (string, error) {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		return validateRegion(candidate)
	}
	return defaultKiroRegion, nil
}
