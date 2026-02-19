package hitl

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/enterprise/agent-platform/internal/audit"
	"github.com/enterprise/agent-platform/pkg/logger"
	"github.com/redis/go-redis/v9"
)

type ReviewStatus string

const (
	ReviewPending  ReviewStatus = "pending"
	ReviewApproved ReviewStatus = "approved"
	ReviewRejected ReviewStatus = "rejected"
	ReviewModified ReviewStatus = "modified"
	ReviewExpired  ReviewStatus = "expired"
)

type Review struct {
	ID            string                 `json:"id"`
	TaskID        string                 `json:"task_id"`
	CorrelationID string                 `json:"correlation_id"`
	OrgID         string                 `json:"org_id"`
	RequesterID   string                 `json:"requester_id"`
	ToolName      string                 `json:"tool_name"`
	InputArgs     map[string]interface{} `json:"input_args"`
	RiskScore     float64                `json:"risk_score"`
	Question      string                 `json:"question,omitempty"`
	Status        ReviewStatus           `json:"status"`
	ReviewerID    string                 `json:"reviewer_id,omitempty"`
	DecisionNote  string                 `json:"decision_note,omitempty"`
	ModifiedArgs  map[string]interface{} `json:"modified_args,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
}

type Decision struct {
	ReviewID     string                 `json:"review_id"`
	ReviewerID   string                 `json:"reviewer_id"`
	Status       ReviewStatus           `json:"status"`
	Note         string                 `json:"note"`
	ModifiedArgs map[string]interface{} `json:"modified_args,omitempty"`
}

type Service struct {
	rdb      *redis.Client
	auditSvc *audit.Service
	sla      time.Duration
}

func NewService(rdb *redis.Client, auditSvc *audit.Service, sla time.Duration) *Service {
	return &Service{
		rdb:      rdb,
		auditSvc: auditSvc,
		sla:      sla,
	}
}

func (s *Service) StartSLAMonitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkExpired(ctx)
			}
		}
	}()
}

func (s *Service) CreateReview(ctx context.Context, review *Review) error {
	review.CreatedAt = time.Now().UTC()
	review.ExpiresAt = review.CreatedAt.Add(s.sla)
	review.Status = ReviewPending

	data, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("marshal review: %w", err)
	}

	key := fmt.Sprintf("hitl:review:%s", review.ID)
	if err := s.rdb.Set(ctx, key, data, s.sla).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}

	// Add to pending set for the org
	orgKey := fmt.Sprintf("hitl:pending:%s", review.OrgID)
	if err := s.rdb.SAdd(ctx, orgKey, review.ID).Err(); err != nil {
		return fmt.Errorf("redis sadd: %w", err)
	}

	return nil
}

func (s *Service) ListPending(ctx context.Context, orgID string) ([]string, error) {
	orgKey := fmt.Sprintf("hitl:pending:%s", orgID)
	ids, err := s.rdb.SMembers(ctx, orgKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis smembers: %w", err)
	}
	return ids, nil
}

func (s *Service) Get(ctx context.Context, reviewID string) (*Review, error) {
	key := fmt.Sprintf("hitl:review:%s", reviewID)
	data, err := s.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("review not found")
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}

	var review Review
	if err := json.Unmarshal([]byte(data), &review); err != nil {
		return nil, fmt.Errorf("unmarshal review: %w", err)
	}
	return &review, nil
}

func (s *Service) Decide(ctx context.Context, d Decision) error {
	log := logger.FromContext(ctx)

	review, err := s.Get(ctx, d.ReviewID)
	if err != nil {
		return err
	}

	if review.Status != ReviewPending {
		return fmt.Errorf("review is not pending (status: %s)", review.Status)
	}

	review.Status = d.Status
	review.ReviewerID = d.ReviewerID
	review.DecisionNote = d.Note
	review.ModifiedArgs = d.ModifiedArgs

	// Update review in Redis
	data, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("marshal review: %w", err)
	}
	key := fmt.Sprintf("hitl:review:%s", review.ID)
	// Keep the record for 24h after decision
	if err := s.rdb.Set(ctx, key, data, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}

	// Remove from pending set
	orgKey := fmt.Sprintf("hitl:pending:%s", review.OrgID)
	if err := s.rdb.SRem(ctx, orgKey, review.ID).Err(); err != nil {
		return fmt.Errorf("redis srem: %w", err)
	}

	// Audit log
	s.auditSvc.NewEvent(review.CorrelationID, "hitl.decision").
		WithActor(audit.ActorUser, d.ReviewerID, "").
		WithResource("review", review.ID, review.OrgID).
		WithTask(review.TaskID).
		WithOutcome(audit.OutcomeSuccess).
		WithMeta("decision", d.Status).
		Emit(ctx)

	log.Info("review decided",
		logger.Str("review_id", review.ID),
		logger.Str("decision", string(d.Status)),
	)

	return nil
}

func (s *Service) checkExpired(ctx context.Context) {
	// Implementation would scan for expired keys or use a sorted set for expiry
	// For simplicity, we rely on Redis TTL for now, but in a real system we might want to
	// actively fail the task when it expires.
	// This skeleton is sufficient for the immediate requirement.
}
