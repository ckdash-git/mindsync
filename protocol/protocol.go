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
	MessageTypeTask       MessageType = "task"        // server -> agent: run this
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

// ModelTier is "which model answers" — one of the three independent tiers
// SRV-47 requires the user be able to choose, separately from where the
// work runs. Deliberately a string, not an int enum: it travels over the
// wire and gets stored/displayed as-is.
type ModelTier string

const (
	TierOnPC    ModelTier = "on-pc"   // the model on the PC that ran the task
	TierPrivate ModelTier = "private" // the company's own model
	TierPublic  ModelTier = "public"  // an external provider
)

// TaskMessage: server -> agent. Dispatches one task down the held
// connection. TaskID is a string (not int64) so the agent never needs to
// know anything about the server's storage — just an opaque identifier to
// echo back in updates. Model is the user's "which model answers" choice
// (SRV-47) — empty/omitted defaults to TierOnPC, since that's the natural
// default for work already running on a PC.
type TaskMessage struct {
	Type   MessageType `json:"type"`
	TaskID string      `json:"task_id"`
	Prompt string      `json:"prompt"`
	Model  ModelTier   `json:"model,omitempty"`
}

// TaskUpdate: agent -> server. Reports where a task stands. Decision and
// Answer are only meaningful once Status is Done; Error is only
// meaningful once Status is Failed or Refused. ModelTier reports which
// tier ACTUALLY answered (SRV-03, PC-17 — the user must be told this,
// since fallback or an override may mean it isn't the tier they picked).
// Overridden/OverrideReason are set when SRV-49/SRV-50 applied: the
// checker moved the choice to something safer and the user must be told
// what happened and why, in plain words.
type TaskUpdate struct {
	Type           MessageType `json:"type"`
	TaskID         string      `json:"task_id"`
	Status         TaskStatus  `json:"status"`
	Decision       string      `json:"decision,omitempty"`
	Answer         string      `json:"answer,omitempty"`
	Error          string      `json:"error,omitempty"`
	ModelTier      ModelTier   `json:"model_tier,omitempty"`
	Overridden     bool        `json:"overridden,omitempty"`
	OverrideReason string      `json:"override_reason,omitempty"`
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