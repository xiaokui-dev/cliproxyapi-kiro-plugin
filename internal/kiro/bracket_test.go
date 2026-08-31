package kiro

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractBracketToolCalls(t *testing.T) {
	maps := &toolNameMaps{fromKiroMap: map[string]string{"short_name": "original_tool_name"}}
	text, calls := extractBracketToolCalls(
		`Before [Called short_name with args: {"items":["a]b",{"nested":true}]}] after.`,
		maps,
	)

	if text != "Before  after." {
		t.Fatalf("unexpected cleaned text: %q", text)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one bracket call, got %d", len(calls))
	}
	if calls[0].name != "original_tool_name" || !json.Valid(calls[0].input) {
		t.Fatalf("unexpected parsed call: %+v", calls[0])
	}
	if !strings.HasPrefix(calls[0].id, "call_") {
		t.Fatalf("unexpected call id: %q", calls[0].id)
	}
}

func TestExtractMultipleAndDropPlaceholder(t *testing.T) {
	text, calls := extractBracketToolCalls(
		`[Called first with args: {"x":1}] middle [Called no_tool_available with args: {}]`,
		&toolNameMaps{},
	)

	if text != "middle" {
		t.Fatalf("unexpected cleaned text: %q", text)
	}
	if len(calls) != 1 || calls[0].name != "first" {
		t.Fatalf("unexpected calls: %+v", calls)
	}
}

func TestAggregateEventsDeduplicatesStructuredAndBracketCalls(t *testing.T) {
	events := []cwEvent{
		{Kind: cwEventToolUse, Name: "lookup", ToolUseID: "tool_1", Text: `{"q":"test"}`},
		{Kind: cwEventContent, Text: `[Called lookup with args: { "q": "test" }]`},
	}

	text, calls := aggregateEvents(events, &toolNameMaps{})
	if text != "" {
		t.Fatalf("expected bracket syntax to be removed, got %q", text)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one deduplicated call, got %d: %+v", len(calls), calls)
	}
	if calls[0].id != "tool_1" {
		t.Fatalf("structured tool call should win deduplication, got id %q", calls[0].id)
	}
}

func TestInvalidBracketToolCallRemainsText(t *testing.T) {
	input := `Keep [Called lookup with args: not-json] visible.`
	text, calls := extractBracketToolCalls(input, &toolNameMaps{})
	if text != input || len(calls) != 0 {
		t.Fatalf("invalid call should remain text: text=%q calls=%+v", text, calls)
	}
}
