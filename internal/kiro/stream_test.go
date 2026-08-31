package kiro

import (
	"encoding/json"
	"strings"
	"testing"
)

// sseEventType extracts the "event:" line value from an SSE chunk payload.
func sseEventType(payload []byte) string {
	for _, line := range strings.Split(string(payload), "\n") {
		if strings.HasPrefix(line, "event: ") {
			return strings.TrimPrefix(line, "event: ")
		}
	}
	return ""
}

func sseData(payload []byte) string {
	for _, line := range strings.Split(string(payload), "\n") {
		if strings.HasPrefix(line, "data: ") {
			return strings.TrimPrefix(line, "data: ")
		}
	}
	return ""
}

func TestStreamChunksTextOnly(t *testing.T) {
	chunks := buildClaudeStreamChunks("Hello world", nil, "claude-sonnet-4-5", 10)

	got := make([]string, 0, len(chunks))
	for _, c := range chunks {
		got = append(got, sseEventType(c.Payload))
	}
	want := []string{
		"message_start",
		"content_block_start",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("event sequence mismatch:\n got=%v\nwant=%v", got, want)
	}

	// Each chunk must be a well-formed SSE event terminated by a blank line.
	for i, c := range chunks {
		if !strings.HasSuffix(string(c.Payload), "\n\n") {
			t.Fatalf("chunk %d not terminated by blank line: %q", i, c.Payload)
		}
	}

	// The text delta must carry the full text.
	var delta struct {
		Delta struct {
			Text string `json:"text"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(sseData(chunks[2].Payload)), &delta); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	if delta.Delta.Text != "Hello world" {
		t.Fatalf("unexpected delta text: %q", delta.Delta.Text)
	}

	// Final stop_reason must be end_turn for a text-only response.
	if !strings.Contains(sseData(chunks[4].Payload), `"stop_reason":"end_turn"`) {
		t.Fatalf("expected end_turn in message_delta: %s", sseData(chunks[4].Payload))
	}
}

func TestStreamChunksWithToolUse(t *testing.T) {
	calls := []toolCall{{id: "t1", name: "get_weather", input: json.RawMessage(`{"city":"NYC"}`)}}
	chunks := buildClaudeStreamChunks("", calls, "claude-sonnet-4-5", 10)

	got := make([]string, 0, len(chunks))
	for _, c := range chunks {
		got = append(got, sseEventType(c.Payload))
	}
	// No text block, so: message_start, tool block start/delta/stop, message_delta, message_stop.
	want := []string{
		"message_start",
		"content_block_start",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("event sequence mismatch:\n got=%v\nwant=%v", got, want)
	}

	// tool_use block start must include id and name.
	start := sseData(chunks[1].Payload)
	if !strings.Contains(start, `"type":"tool_use"`) || !strings.Contains(start, `"id":"t1"`) || !strings.Contains(start, `"name":"get_weather"`) {
		t.Fatalf("unexpected tool_use start: %s", start)
	}
	// input arrives as an input_json_delta partial_json string.
	deltaData := sseData(chunks[2].Payload)
	if !strings.Contains(deltaData, `"type":"input_json_delta"`) {
		t.Fatalf("expected input_json_delta: %s", deltaData)
	}
	// stop_reason must be tool_use.
	if !strings.Contains(sseData(chunks[4].Payload), `"stop_reason":"tool_use"`) {
		t.Fatalf("expected tool_use stop_reason: %s", sseData(chunks[4].Payload))
	}
}
