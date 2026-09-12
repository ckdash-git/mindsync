// Package protocol defines the messages sent over the held broker
// connection between server and agent (SRV-18/§9.9). It lives here, not
// duplicated in both repos, for the same reason the checker does: server
// and agent must agree on exactly one wire format, or they silently drift.
package protocol

import "encoding/json"

// MessageType discriminates the flat JSON envelope below. Every message
// either direction sends over the websocket has this field.
type MessageType string

const (
	MessageTypeTask       MessageType = "task"       // server -> agent: run this
	MessageTypeTaskUpdate MessageType = "task_update" // agent -> server: status/result
)

// TaskStatus tracks a task's lifecycle. SRV-24's spirit: a task is never
// silently dropped — it moves through these states or ends in Failed with
// a reason, never just vanishes.
type TaskStatus string

const (
	TaskQueued  TaskStatus = "queued"  // created, agent not yet confirmed to have it
	TaskSent    TaskStatus = "sent"    // handed to the agent's connection
	TaskRunning TaskStatus = "running" // agent confirmed receipt, working on it
	TaskDone    TaskStatus = "done"    // completed, see Decision/Answer
	TaskRefused TaskStatus = "refused" // the agent's own local check refused it
	TaskFailed  TaskStatus = "failed"  // couldn't complete — see Error
)

// TaskMessage: server -> agent. Dispatches one task down the held
// connection. TaskID is a string (not int64) so the agent never needs to
// know anything about the server's storage — just an opaque identifier to
// echo back in updates.
type TaskMessage struct {
	Type   MessageType `json:"type"`
	TaskID string      `json:"task_id"`
	Prompt string      `json:"prompt"`
}

// TaskUpdate: agent -> server. Reports where a task stands. Decision and
// Answer are only meaningful once Status is Done; Error is only
// meaningful once Status is Failed or Refused.
type TaskUpdate struct {
	Type     MessageType `json:"type"`
	TaskID   string      `json:"task_id"`
	Status   TaskStatus  `json:"status"`
	Decision string      `json:"decision,omitempty"`
	Answer   string      `json:"answer,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// envelopeType is used to peek at a raw message's "type" field before
// deciding which concrete struct to unmarshal it into.
type envelopeType struct {
	Type MessageType `json:"type"`
}

// ParseMessage inspects raw JSON from the held connection and returns
// exactly one of (*TaskMessage, *TaskUpdate), or an error if the type
// field is missing/unrecognized. Both server and agent read loops should
// go through this rather than unmarshalling into a guessed type directly.
func ParseMessage(raw []byte) (task *TaskMessage, update *TaskUpdate, err error) {
	var env envelopeType
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, err
	}
	switch env.Type {
	case MessageTypeTask:
		var t TaskMessage
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, nil, err
		}
		return &t, nil, nil
	case MessageTypeTaskUpdate:
		var u TaskUpdate
		if err := json.Unmarshal(raw, &u); err != nil {
			return nil, nil, err
		}
		return nil, &u, nil
	default:
		return nil, nil, &UnknownMessageTypeError{Type: env.Type}
	}
}

type UnknownMessageTypeError struct {
	Type MessageType
}

func (e *UnknownMessageTypeError) Error() string {
	return "protocol: unknown message type " + string(e.Type)
}