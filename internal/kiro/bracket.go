package kiro

import (
	"encoding/json"
	"regexp"
	"strings"
)

// bracketCallNamePattern matches the header of a text-form tool call that the
// model sometimes emits inline instead of a structured toolUse event:
//
//	[Called some_tool with args: {"a": 1}]
var bracketCallNamePattern = regexp.MustCompile(`(?i)\[Called\s+(\w+)\s+with\s+args:`)

// extractBracketToolCalls finds inline "[Called name with args: {json}]" tool
// calls in text, returns the text with those spans removed and the parsed calls
// with names restored to their original (pre-Kiro) form. The placeholder tool is
// dropped. When there is nothing to extract, the original text is returned as-is.
func extractBracketToolCalls(text string, maps *toolNameMaps) (string, []toolCall) {
	if !strings.Contains(text, "[Called") {
		return text, nil
	}

	// Collect the start offsets of every "[Called" occurrence in order.
	positions := make([]int, 0, 4)
	for start := 0; ; {
		pos := strings.Index(text[start:], "[Called")
		if pos == -1 {
			break
		}
		positions = append(positions, start+pos)
		start = start + pos + 1
	}

	calls := make([]toolCall, 0, len(positions))
	// Removal spans in the original text, kept in increasing, non-overlapping order.
	type span struct{ start, end int }
	spans := make([]span, 0, len(positions))

	for i, startPos := range positions {
		limit := len(text)
		if i+1 < len(positions) {
			limit = positions[i+1]
		}
		segment := text[startPos:limit]

		end := findMatchingBracket(segment, 0)
		if end == -1 {
			// Fallback: use the last ']' in the segment, matching the reference.
			end = strings.LastIndex(segment, "]")
			if end == -1 {
				continue
			}
		}
		toolCallText := segment[:end+1]

		call, ok := parseSingleBracketToolCall(toolCallText, maps)
		if !ok {
			continue
		}
		if call.name != kiroPlaceholderToolName {
			calls = append(calls, call)
		}
		spans = append(spans, span{start: startPos, end: startPos + len(toolCallText)})
	}

	if len(spans) == 0 {
		return text, calls
	}

	// Rebuild the text without the matched tool-call spans.
	var sb strings.Builder
	prev := 0
	for _, s := range spans {
		if s.start > prev {
			sb.WriteString(text[prev:s.start])
		}
		prev = s.end
	}
	if prev < len(text) {
		sb.WriteString(text[prev:])
	}
	return strings.TrimSpace(sb.String()), calls
}

// parseSingleBracketToolCall parses one "[Called name with args: {json}]" chunk.
// It returns false when the header, argument bounds, or JSON object are unusable.
func parseSingleBracketToolCall(toolCallText string, maps *toolNameMaps) (toolCall, bool) {
	m := bracketCallNamePattern.FindStringSubmatch(toolCallText)
	if m == nil {
		return toolCall{}, false
	}
	name := strings.TrimSpace(m[1])

	const marker = "with args:"
	argsStart := strings.Index(strings.ToLower(toolCallText), marker)
	if argsStart == -1 {
		return toolCall{}, false
	}
	argsStart += len(marker)
	argsEnd := strings.LastIndex(toolCallText, "]")
	if argsEnd <= argsStart {
		return toolCall{}, false
	}

	candidate := strings.TrimSpace(toolCallText[argsStart:argsEnd])
	var args any
	if err := json.Unmarshal([]byte(candidate), &args); err != nil || args == nil {
		return toolCall{}, false
	}
	if _, isObject := args.(map[string]any); !isObject {
		return toolCall{}, false
	}
	canonical, err := json.Marshal(args)
	if err != nil {
		return toolCall{}, false
	}

	return toolCall{
		id:    "call_" + randomHexN(4),
		name:  maps.fromKiro(name),
		input: canonical,
	}, true
}

// findMatchingBracket returns the index (within s) of the ']' that closes the
// '[' at startPos, honoring bracket nesting and JSON string literals. Returns
// -1 when there is no match. Mirrors the reference implementation.
func findMatchingBracket(s string, startPos int) int {
	if startPos >= len(s) || s[startPos] != '[' {
		return -1
	}
	depth := 1
	inString := false
	escape := false
	for i := startPos + 1; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// dedupToolCalls removes duplicate tool calls keyed by name + input, preserving
// first-seen order.
func dedupToolCalls(calls []toolCall) []toolCall {
	seen := make(map[string]struct{}, len(calls))
	out := make([]toolCall, 0, len(calls))
	for _, c := range calls {
		key := c.name + "|" + canonicalToolInput(c.input)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func canonicalToolInput(input json.RawMessage) string {
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return string(input)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return string(input)
	}
	return string(canonical)
}
