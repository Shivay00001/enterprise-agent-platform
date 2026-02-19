package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/enterprise/agent-platform/pkg/crypto"
	apperr "github.com/enterprise/agent-platform/pkg/errors"
	"github.com/enterprise/agent-platform/pkg/logger"
)

// Outcome represents the result of an audited action.
type Outcome string

const (
	OutcomeSuccess   Outcome = "success"
	OutcomeFailure   Outcome = "failure"
	OutcomeBlocked   Outcome = "blocked"
	OutcomeEscalated Outcome = "escalated"
)

// ActorType distinguishes who performed the action.
type ActorType string

const (
	ActorUser    ActorType = "user"
	ActorService ActorType = "service"
	ActorAgent   ActorType = "agent"
	ActorSystem  ActorType = "system"
)

// Actor represents the entity that performed an action.
type Actor struct {
	Type ActorType `json:"type"`
	ID   string    `json:"id"`
	IP   string    `json:"ip,omitempty"`
}

// Resource identifies the object of an action.
type Resource struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	OrgID string `json:"org_id,omitempty"`
}

// Event is a single, immutable audit record.
type Event struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	TaskID        string                 `json:"task_id,omitempty"`
	Service       string                 `json:"service"`
	Actor         Actor                  `json:"actor"`
	Action        string                 `json:"action"`
	Resource      Resource               `json:"resource"`
	Outcome       Outcome                `json:"outcome"`
	RiskScore     float64                `json:"risk_score,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	PrevHash      string                 `json:"prev_hash"` // cryptographic chain
	Hash          string                 `json:"hash"`      // hash of this event
}

// Service writes audit events to the immutable audit log.
type Service struct {
	nc          *nats.Conn
	js          nats.JetStreamContext
	serviceName string
	encKey      []byte
	mu          sync.Mutex
	lastHash    string
}

// NewService creates a new audit service.
func NewService(nc *nats.Conn, serviceName string, encryptionKey []byte) (*Service, error) {
	if nc == nil {
		return &Service{
			serviceName: serviceName,
			encKey:      encryptionKey,
			lastHash:    "genesis",
		}, nil
	}
	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("get jetstream context: %w", err)
	}

	// Ensure the audit stream exists with correct settings.
	_, err = js.StreamInfo("AUDIT")
	if err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      "AUDIT",
			Subjects:  []string{"audit.>"},
			Storage:   nats.FileStorage, // Persistent, not memory.
			Retention: nats.LimitsPolicy,
			MaxAge:    7 * 365 * 24 * time.Hour, // 7-year retention.
			Replicas:  3,                        // Replicated for durability.
			Discard:   nats.DiscardOld,
		})
		if err != nil {
			return nil, fmt.Errorf("create audit stream: %w", err)
		}
	}

	return &Service{
		nc:          nc,
		js:          js,
		serviceName: serviceName,
		encKey:      encryptionKey,
		lastHash:    "genesis", // Hash chain starts here.
	}, nil
}

// Log writes an audit event. This is the primary entrypoint.
// It is safe to call from multiple goroutines.
func (s *Service) Log(ctx context.Context, event Event) error {
	log := logger.FromContext(ctx)

	// Fill in server-side fields.
	eventID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate event ID: %w", err)
	}
	event.ID = eventID.String()
	event.Timestamp = time.Now().UTC()
	event.Service = s.serviceName

	// Build the cryptographic chain: lock to ensure ordering.
	s.mu.Lock()
	event.PrevHash = s.lastHash
	eventJSON, err := json.Marshal(event)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("marshal event: %w", err)
	}
	event.Hash = crypto.ChainHash(s.lastHash, eventJSON)
	s.lastHash = event.Hash
	s.mu.Unlock()

	// Re-marshal with the hash included.
	finalJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal final event: %w", err)
	}

	// Publish to NATS JetStream. Subject encodes service and action for routing.
	subject := fmt.Sprintf("audit.%s.%s", s.serviceName, sanitizeAction(event.Action))

	if s.js == nil {
		log.Debug("audit event (no nats)",
			logger.Str("event_id", event.ID),
			logger.Str("action", event.Action),
		)
		return nil
	}

	_, pubErr := s.js.PublishAsync(subject, finalJSON)
	if pubErr != nil {
		log.Error("failed to publish audit event",
			logger.Str("event_id", event.ID),
			logger.Str("action", event.Action),
			logger.Err(pubErr),
		)
		return fmt.Errorf("publish audit event: %w", pubErr)
	}

	log.Debug("audit event logged",
		logger.Str("event_id", event.ID),
		logger.Str("action", event.Action),
		logger.Str("outcome", string(event.Outcome)),
	)
	return nil
}

// LogTaskEvent is a convenience wrapper for task-related audit events.
func (s *Service) LogTaskEvent(
	ctx context.Context,
	correlationID, taskID string,
	actor Actor,
	action string,
	resource Resource,
	outcome Outcome,
	riskScore float64,
	metadata map[string]interface{},
	auditErr error,
) {
	event := Event{
		CorrelationID: correlationID,
		TaskID:        taskID,
		Actor:         actor,
		Action:        action,
		Resource:      resource,
		Outcome:       outcome,
		RiskScore:     riskScore,
		Metadata:      metadata,
	}
	if auditErr != nil {
		event.ErrorMessage = auditErr.Error()
	}
	// Best-effort: audit failures should never crash the calling service.
	_ = s.Log(ctx, event)
}

// LogSecurityEvent logs a security-specific event with high severity.
func (s *Service) LogSecurityEvent(
	ctx context.Context,
	correlationID string,
	actor Actor,
	threatType string,
	details map[string]interface{},
) {
	event := Event{
		CorrelationID: correlationID,
		Actor:         actor,
		Action:        "security.threat_detected",
		Resource:      Resource{Type: "security", ID: threatType},
		Outcome:       OutcomeBlocked,
		RiskScore:     1.0,
		Metadata:      details,
	}
	_ = s.Log(ctx, event)
}

// EventBuilder provides a fluent API for constructing audit events.
type EventBuilder struct {
	svc   *Service
	event Event
}

// NewEvent returns a builder for a new audit event.
func (s *Service) NewEvent(correlationID, action string) *EventBuilder {
	return &EventBuilder{
		svc: s,
		event: Event{
			CorrelationID: correlationID,
			Action:        action,
			Outcome:       OutcomeSuccess,
			Metadata:      make(map[string]interface{}),
		},
	}
}

func (b *EventBuilder) WithActor(t ActorType, id, ip string) *EventBuilder {
	b.event.Actor = Actor{Type: t, ID: id, IP: ip}
	return b
}

func (b *EventBuilder) WithResource(resourceType, id, orgID string) *EventBuilder {
	b.event.Resource = Resource{Type: resourceType, ID: id, OrgID: orgID}
	return b
}

func (b *EventBuilder) WithOutcome(o Outcome) *EventBuilder {
	b.event.Outcome = o
	return b
}

func (b *EventBuilder) WithRiskScore(score float64) *EventBuilder {
	b.event.RiskScore = score
	return b
}

func (b *EventBuilder) WithTask(taskID string) *EventBuilder {
	b.event.TaskID = taskID
	return b
}

func (b *EventBuilder) WithMeta(key string, value interface{}) *EventBuilder {
	b.event.Metadata[key] = value
	return b
}

func (b *EventBuilder) WithError(err error) *EventBuilder {
	if err != nil {
		ae := apperr.AsAppError(err)
		b.event.ErrorMessage = ae.Error()
		b.event.Outcome = OutcomeFailure
	}
	return b
}

func (b *EventBuilder) Emit(ctx context.Context) error {
	return b.svc.Log(ctx, b.event)
}

// sanitizeAction converts an action string to a NATS-safe subject component.
func sanitizeAction(action string) string {
	result := make([]byte, len(action))
	for i := 0; i < len(action); i++ {
		c := action[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}
