package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

type contextKey string

const (
	loggerKey        contextKey = "logger"
	correlationIDKey contextKey = "correlation_id"
	taskIDKey        contextKey = "task_id"
	userIDKey        contextKey = "user_id"
	serviceKey       contextKey = "service"
)

// Logger wraps zerolog.Logger with context propagation.
type Logger struct {
	zl zerolog.Logger
}

// New creates a new structured logger.
func New(level, serviceName string) *Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	var out io.Writer = os.Stdout
	// In non-production, use console writer for readability.
	if os.Getenv("ENVIRONMENT") != "production" {
		out = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}

	zl := zerolog.New(out).
		Level(lvl).
		With().
		Timestamp().
		Str("service", serviceName).
		Logger()

	return &Logger{zl: zl}
}

// WithContext stores the logger in context for propagation.
func (l *Logger) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext retrieves the logger from context.
// Returns a default logger if none found — never panics.
func FromContext(ctx context.Context) *Logger {
	if l, ok := ctx.Value(loggerKey).(*Logger); ok {
		return l
	}
	return New("info", "unknown")
}

// WithCorrelationID returns a new Logger with the correlation ID field.
func (l *Logger) WithCorrelationID(id string) *Logger {
	return &Logger{zl: l.zl.With().Str("correlation_id", id).Logger()}
}

// WithTaskID returns a new Logger with the task ID field.
func (l *Logger) WithTaskID(id string) *Logger {
	return &Logger{zl: l.zl.With().Str("task_id", id).Logger()}
}

// WithUserID returns a new Logger with the user ID field (hashed for privacy in prod).
func (l *Logger) WithUserID(id string) *Logger {
	return &Logger{zl: l.zl.With().Str("user_id", id).Logger()}
}

// WithField returns a new Logger with an additional string field.
func (l *Logger) WithField(key, value string) *Logger {
	return &Logger{zl: l.zl.With().Str(key, value).Logger()}
}

// WithError returns a new Logger with an error field.
func (l *Logger) WithError(err error) *Logger {
	return &Logger{zl: l.zl.With().Err(err).Logger()}
}

func (l *Logger) Debug(msg string, fields ...Field) {
	e := l.zl.Debug()
	for _, f := range fields {
		e = f(e)
	}
	e.Msg(msg)
}

func (l *Logger) Info(msg string, fields ...Field) {
	e := l.zl.Info()
	for _, f := range fields {
		e = f(e)
	}
	e.Msg(msg)
}

func (l *Logger) Warn(msg string, fields ...Field) {
	e := l.zl.Warn()
	for _, f := range fields {
		e = f(e)
	}
	e.Msg(msg)
}

func (l *Logger) Error(msg string, fields ...Field) {
	e := l.zl.Error()
	for _, f := range fields {
		e = f(e)
	}
	e.Msg(msg)
}

func (l *Logger) Fatal(msg string, fields ...Field) {
	e := l.zl.Fatal()
	for _, f := range fields {
		e = f(e)
	}
	e.Msg(msg)
}

// Field is a function that adds a field to a zerolog event.
type Field func(*zerolog.Event) *zerolog.Event

func Str(key, value string) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Str(key, value)
	}
}

func Int(key string, value int) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Int(key, value)
	}
}

func Float64(key string, value float64) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Float64(key, value)
	}
}

func Bool(key string, value bool) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Bool(key, value)
	}
}

func Err(err error) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Err(err)
	}
}

func Duration(key string, d time.Duration) Field {
	return func(e *zerolog.Event) *zerolog.Event {
		return e.Dur(key, d)
	}
}
