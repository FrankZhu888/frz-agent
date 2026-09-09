package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestParseResponsesSEReplay replays a recorded Ark kimi-k3 stream (trimmed:
// redundant reasoning deltas removed) and verifies text accumulation plus
// function_call parsing: call_id/name from output_item.added, arguments
// assembled from deltas.
func TestParseResponsesSEReplay(t *testing.T) {
	data, err := os.ReadFile("testdata/ark_toolcall.sse")
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	var deltas []string
	res, err := parseResponsesSSE(context.Background(), strings.NewReader(string(data)),
		func(d string) { deltas = append(deltas, d) }, nil)
	if err != nil {
		t.Fatalf("parseResponsesSSE: %v", err)
	}
	if len(res.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(res.ToolCalls))
	}
	tc := res.ToolCalls[0]
	if tc.ID != "bash_0" || tc.Name != "bash" {
		t.Errorf("unexpected tool call: id=%q name=%q", tc.ID, tc.Name)
	}
	if tc.Arguments != `{"command":"df -h /"}` {
		t.Errorf("unexpected arguments: %q", tc.Arguments)
	}
	// this stream is a pure tool-call turn: no assistant text
	if res.Text != "" {
		t.Errorf("expected empty text, got %q", res.Text)
	}
}

// TestParseResponsesSEMultiCall verifies call ordering with two interleaved
// function calls (synthetic stream in the recorded Ark shape).
func TestParseResponsesSEMultiCall(t *testing.T) {
	stream := `event: response.created
data: {"type":"response.created"}

event: response.output_item.added
data: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_A","type":"function_call","call_id":"bash_0","name":"bash","status":"in_progress"}}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"fc_A","delta":"{\"command\":\"df"}

event: response.output_item.added
data: {"type":"response.output_item.added","output_index":1,"item":{"id":"fc_B","type":"function_call","call_id":"read_file_1","name":"read_file","status":"in_progress"}}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"fc_A","delta":" -h\"}"}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"fc_B","delta":"{\"path\":\"/var/log/syslog\"}"}

event: response.function_call_arguments.done
data: {"type":"response.function_call_arguments.done","item_id":"fc_A","arguments":"{\"command\":\"df -h\"}"}

event: response.function_call_arguments.done
data: {"type":"response.function_call_arguments.done","item_id":"fc_B","arguments":"{\"path\":\"/var/log/syslog\"}"}

event: response.completed
data: {"type":"response.completed"}
`
	res, err := parseResponsesSSE(context.Background(), strings.NewReader(stream), nil, nil)
	if err != nil {
		t.Fatalf("parseResponsesSSE: %v", err)
	}
	if len(res.ToolCalls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(res.ToolCalls))
	}
	if res.ToolCalls[0].ID != "bash_0" || res.ToolCalls[1].ID != "read_file_1" {
		t.Errorf("call order wrong: %+v", res.ToolCalls)
	}
	if res.ToolCalls[0].Arguments != `{"command":"df -h"}` {
		t.Errorf("call0 args: %q", res.ToolCalls[0].Arguments)
	}
	if res.ToolCalls[1].Arguments != `{"path":"/var/log/syslog"}` {
		t.Errorf("call1 args: %q", res.ToolCalls[1].Arguments)
	}
}

// TestParseResponsesSEFailed verifies upstream errors surface as errors.
func TestParseResponsesSEFailed(t *testing.T) {
	stream := "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"rate limited\"}}}\n"
	_, err := parseResponsesSSE(context.Background(), strings.NewReader(stream), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("expected upstream error, got %v", err)
	}
}

// TestParseResponsesSEText verifies plain text accumulation and onDelta.
func TestParseResponsesSEText(t *testing.T) {
	stream := `event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"Hello"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":" world"}

event: response.completed
data: {"type":"response.completed"}
`
	var deltas []string
	res, err := parseResponsesSSE(context.Background(), strings.NewReader(stream),
		func(d string) { deltas = append(deltas, d) }, nil)
	if err != nil {
		t.Fatalf("parseResponsesSSE: %v", err)
	}
	if res.Text != "Hello world" {
		t.Errorf("text = %q", res.Text)
	}
	if len(deltas) != 2 {
		t.Errorf("onDelta calls = %d", len(deltas))
	}
	if len(res.ToolCalls) != 0 {
		t.Errorf("unexpected tool calls: %+v", res.ToolCalls)
	}
}
