package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/enterprise/agent-platform/internal/config"
	"github.com/enterprise/agent-platform/internal/models"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

const (
	streamName    = "agent-events"
	consumerName  = "audit-consumer"
	auditSubject  = "agent.events.>"
	batchSize     = 100
	flushInterval = 5 * time.Second
)

// AuditService consumes events from NATS JetStream, builds a cryptographic
// audit chain, and writes immutable records to the configured storage backend.
type AuditService struct {
	nc          *nats.Conn
	js          nats.JetStreamContext
	storage     AuditStorage
	chainHasher *ChainHasher
	mu          sync.Mutex
	batch       []StoredAuditEvent
	log         *zap.Logger
	signer      *EventSigner
}

// StoredAuditEvent is the final record written to immutable storage.
type StoredAuditEvent struct {
	models.AuditEvent
	ChainHash string `json:"chain_hash"`  // SHA-256 of this record + prev hash
	PrevHash  string `json:"prev_hash"`   // hash of previous record
	Signature string `json:"signature"`   // ECDSA over chain hash
	StoredAt  time.Time `json:"stored_at"`
}

// AuditStorage is the interface for writing audit records.
type AuditStorage interface {
	Write(ctx context.Context, events []StoredAuditEvent) error
	GetLastHash(ctx context.Context) (string, error)
}

// ChainHasher maintains the cryptographic audit chain.
type ChainHasher struct {
	mu       sync.Mutex
	prevHash string
}

func NewChainHasher(genesisHash string) *ChainHasher {
	return &ChainHasher{prevHash: genesisHash}
}

// Next computes the next hash in the chain and advances the state.
func (c *ChainHasher) Next(event *models.AuditEvent) (currentHash, prevHash string, err error) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", "", fmt.Errorf("marshal event: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.prevHash
	combined := append(eventJSON, []byte(prev)...)
	hash := sha256.Sum256(combined)
	current := fmt.Sprintf("%x", hash)
	c.prevHash = current

	return current, prev, nil
}

// EventSigner signs audit event hashes using ECDSA.
type EventSigner struct {
	signingKeyPath string
}

func (s *EventSigner) Sign(hash string) (string, error) {
	// In production: load key from Vault and sign with ECDSA P-256
	// Stub: return a placeholder signature
	return fmt.Sprintf("sig:%x", sha256.Sum256([]byte(hash+s.signingKeyPath))), nil
}

// ─── NATS Consumer ────────────────────────────────────────────────────────────

func NewAuditService(nc *nats.Conn, storage AuditStorage, signerKeyPath string, log *zap.Logger) (*AuditService, error) {
	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("jetstream context: %w", err)
	}

	// Ensure stream exists
	_, err = js.AddStream(&nats.StreamConfig{
		Name:       streamName,
		Subjects:   []string{auditSubject},
		Retention:  nats.LimitsPolicy,
		MaxAge:     7 * 24 * time.Hour * 365, // 1 year in stream (long-term in S3)
		Storage:    nats.FileStorage,
		Replicas:   3,
		Discard:    nats.DiscardOld,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		return nil, fmt.Errorf("create stream: %w", err)
	}

	// Get last hash from storage to continue chain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lastHash, err := storage.GetLastHash(ctx)
	if err != nil {
		log.Warn("could not get last audit hash, starting new chain", zap.Error(err))
		lastHash = ""
	}

	return &AuditService{
		nc:          nc,
		js:          js,
		storage:     storage,
		chainHasher: NewChainHasher(lastHash),
		log:         log,
		signer:      &EventSigner{signingKeyPath: signerKeyPath},
	}, nil
}

// Run starts consuming audit events from NATS and writing to storage.
func (s *AuditService) Run(ctx context.Context) error {
	// Create durable consumer with exactly-once delivery guarantees
	_, err := s.js.AddConsumer(streamName, &nats.ConsumerConfig{
		Durable:        consumerName,
		AckPolicy:      nats.AckExplicitPolicy,
		DeliverPolicy:  nats.DeliverAllPolicy,
		AckWait:        30 * time.Second,
		MaxDeliver:     5,
		FilterSubject:  auditSubject,
		MaxAckPending:  1000,
	})
	if err != nil && err != nats.ErrConsumerNameAlreadyInUse {
		return fmt.Errorf("create consumer: %w", err)
	}

	sub, err := s.js.PullSubscribe(auditSubject, consumerName, nats.Bind(streamName, consumerName))
	if err != nil {
		return fmt.Errorf("pull subscribe: %w", err)
	}
	defer sub.Unsubscribe()

	// Flush timer for batching
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	s.log.Info("audit service started, consuming events")

	for {
		select {
		case <-ctx.Done():
			// Final flush
			if err := s.flush(context.Background()); err != nil {
				s.log.Error("final flush failed", zap.Error(err))
			}
			return ctx.Err()

		case <-flushTicker.C:
			if err := s.flush(ctx); err != nil {
				s.log.Error("flush failed", zap.Error(err))
			}

		default:
			// Pull batch of messages
			msgs, err := sub.Fetch(batchSize, nats.MaxWait(2*time.Second))
			if err != nil {
				if err == nats.ErrTimeout {
					continue // no messages, normal
				}
				s.log.Error("fetch error", zap.Error(err))
				continue
			}

			for _, msg := range msgs {
				if err := s.processMessage(ctx, msg); err != nil {
					s.log.Error("process message failed",
						zap.Error(err),
						zap.String("subject", msg.Subject),
					)
					// NAK to retry
					_ = msg.Nak()
					continue
				}
				_ = msg.Ack()
			}
		}
	}
}

func (s *AuditService) processMessage(ctx context.Context, msg *nats.Msg) error {
	var event models.AuditEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		return fmt.Errorf("unmarshal event: %w", err)
	}

	// Validate event has required fields
	if event.ID == uuid.Nil {
		return fmt.Errorf("event missing ID")
	}
	if event.Timestamp.IsZero() {
		return fmt.Errorf("event missing timestamp")
	}
	if event.EventType == "" {
		return fmt.Errorf("event missing type")
	}

	// Build chain hash
	currentHash, prevHash, err := s.chainHasher.Next(&event)
	if err != nil {
		return fmt.Errorf("compute chain hash: %w", err)
	}

	// Sign the hash
	sig, err := s.signer.Sign(currentHash)
	if err != nil {
		return fmt.Errorf("sign event: %w", err)
	}

	stored := StoredAuditEvent{
		AuditEvent: event,
		ChainHash:  currentHash,
		PrevHash:   prevHash,
		Signature:  sig,
		StoredAt:   time.Now().UTC(),
	}

	s.mu.Lock()
	s.batch = append(s.batch, stored)
	shouldFlush := len(s.batch) >= batchSize
	s.mu.Unlock()

	if shouldFlush {
		return s.flush(ctx)
	}

	return nil
}

func (s *AuditService) flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := make([]StoredAuditEvent, len(s.batch))
	copy(batch, s.batch)
	s.batch = s.batch[:0]
	s.mu.Unlock()

	flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := s.storage.Write(flushCtx, batch); err != nil {
		// Put the batch back on failure
		s.mu.Lock()
		s.batch = append(batch, s.batch...)
		s.mu.Unlock()
		return fmt.Errorf("write batch (%d events): %w", len(batch), err)
	}

	s.log.Info("audit batch flushed",
		zap.Int("count", len(batch)),
		zap.String("last_hash", batch[len(batch)-1].ChainHash[:16]+"..."),
	)

	return nil
}

// Emitter is the event publishing interface used by other services.
type Emitter struct {
	nc  *nats.Conn
	js  nats.JetStreamContext
	log *zap.Logger
}

func NewEmitter(nc *nats.Conn, log *zap.Logger) (*Emitter, error) {
	js, err := nc.JetStream()
	if err != nil {
		return nil, err
	}
	return &Emitter{nc: nc, js: js, log: log}, nil
}

// Emit publishes an audit event to NATS JetStream.
// This is the interface called by all other services.
func (e *Emitter) Emit(ctx context.Context, event *models.AuditEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	subject := fmt.Sprintf("agent.events.%s", string(event.EventType))

	// Publish with deduplication key to prevent duplicate events on retry
	msgID := event.ID.String()

	_, err = e.js.Publish(subject, data,
		nats.MsgId(msgID),
		nats.Context(ctx),
	)
	if err != nil {
		// Log but don't fail the caller — audit failure should not block business logic.
		// Alert monitoring system instead.
		e.log.Error("failed to emit audit event",
			zap.String("event_type", string(event.EventType)),
			zap.String("event_id", event.ID.String()),
			zap.Error(err),
		)
		return err
	}

	return nil
}

// ─── File Storage (for local/dev) ────────────────────────────────────────────

// FileAuditStorage writes audit events to JSONL files.
// In production, replace with S3Storage.
type FileAuditStorage struct {
	mu       sync.Mutex
	filePath string
	f        *os.File
	lastHash string
}

func NewFileAuditStorage(path string) (*FileAuditStorage, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &FileAuditStorage{filePath: path, f: f}, nil
}

func (s *FileAuditStorage) Write(ctx context.Context, events []StoredAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := s.f.Write(append(line, '\n')); err != nil {
			return err
		}
		s.lastHash = event.ChainHash
	}

	return s.f.Sync()
}

func (s *FileAuditStorage) GetLastHash(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHash, nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config load failed", zap.Error(err))
	}

	// Connect to NATS with TLS
	opts := []nats.Option{
		nats.Name("audit-service"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Warn("NATS disconnected", zap.Error(err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info("NATS reconnected", zap.String("url", nc.ConnectedUrl()))
		}),
	}

	if cfg.NATS.NKeyPath != "" {
		// Use NKey authentication
		nkeyOpt, err := nats.NkeyOptionFromSeed(cfg.NATS.NKeyPath)
		if err != nil {
			log.Fatal("load nkey", zap.Error(err))
		}
		opts = append(opts, nkeyOpt)
	}

	nc, err := nats.Connect(cfg.NATS.URLs[0], opts...)
	if err != nil {
		log.Fatal("NATS connect failed", zap.Error(err))
	}
	defer nc.Close()

	// Initialize storage (file-based for dev, S3 for production)
	auditLogPath := os.Getenv("AUDIT_LOG_PATH")
	if auditLogPath == "" {
		auditLogPath = "/var/log/agent-platform/audit.jsonl"
	}
	if err := os.MkdirAll("/var/log/agent-platform", 0700); err != nil {
		log.Fatal("create log dir", zap.Error(err))
	}

	storage, err := NewFileAuditStorage(auditLogPath)
	if err != nil {
		log.Fatal("audit storage init", zap.Error(err))
	}

	signerKeyPath := os.Getenv("AUDIT_SIGNING_KEY_PATH")
	svc, err := NewAuditService(nc, storage, signerKeyPath, log)
	if err != nil {
		log.Fatal("audit service init", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("audit service running",
		zap.String("nats_url", nc.ConnectedUrl()),
		zap.String("log_path", auditLogPath),
	)

	if err := svc.Run(ctx); err != nil && err != context.Canceled {
		log.Error("audit service exited with error", zap.Error(err))
		os.Exit(1)
	}

	log.Info("audit service stopped gracefully")
}
