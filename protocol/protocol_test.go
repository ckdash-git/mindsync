package protocol

import (
	"encoding/json"
	"testing"
)

func TestParseTaskMessage(t *testing.T) {
	raw := `{"type":"task","task_id":"abc-123","prompt":"summarize this"}`
	task, update, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if update != nil {
		t.Fatal("expected update to be nil for a task message")
	}
	if task == nil || task.TaskID != "abc-123" || task.Prompt != "summarize this" {
		t.Fatalf("unexpected task: %+v", task)
	}
}

func TestParseTaskUpdate(t *testing.T) {
	raw := `{"type":"task_update","task_id":"abc-123","status":"done","decision":"allow","answer":"here you go"}`
	task, update, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task != nil {
		t.Fatal("expected task to be nil for an update message")
	}
	if update == nil || update.Status != TaskDone || update.Decision != "allow" {
		t.Fatalf("unexpected update: %+v", update)
	}
}

func TestParseUnknownType(t *testing.T) {
	raw := `{"type":"something_else"}`
	_, _, err := ParseMessage([]byte(raw))
	if err == nil {
		t.Fatal("expected an error for an unrecognized message type")
	}
}

func TestParseMalformedJSON(t *testing.T) {
	_, _, err := ParseMessage([]byte(`not json at all`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestTaskMessageRoundTrip(t *testing.T) {
	original := TaskMessage{Type: MessageTypeTask, TaskID: "t-1", Prompt: "hello"}
	task, _, err := ParseMessage(mustMarshal(t, original))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *task != original {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", *task, original)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	return b
}