package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors for the domain.
var (
	ErrNotFound           = New("not_found", "resource not found", http.StatusNotFound)
	ErrUnauthorized       = New("unauthorized", "authentication required", http.StatusUnauthorized)
	ErrForbidden          = New("forbidden", "insufficient permissions", http.StatusForbidden)
	ErrValidation         = New("validation_error", "request validation failed", http.StatusBadRequest)
	ErrRateLimited        = New("rate_limited", "rate limit exceeded", http.StatusTooManyRequests)
	ErrTaskBudgetExceeded = New("budget_exceeded", "task budget exceeded", http.StatusPaymentRequired)
	ErrPromptInjection    = New("prompt_injection", "prompt injection detected", http.StatusBadRequest)
	ErrToolForbidden      = New("tool_forbidden", "tool not permitted for this context", http.StatusForbidden)
	ErrComplianceBlock    = New("compliance_block", "action blocked by compliance policy", http.StatusForbidden)
	ErrHITLRequired       = New("hitl_required", "human review required before proceeding", http.StatusAccepted)
	ErrAgentStuck         = New("agent_stuck", "agent exceeded iteration limit", http.StatusInternalServerError)
	ErrSSRFBlocked        = New("ssrf_blocked", "request to internal network blocked", http.StatusForbidden)
	ErrRobotsBlocked      = New("robots_blocked", "disallowed by robots.txt", http.StatusForbidden)
	ErrInternalServer     = New("internal_error", "internal server error", http.StatusInternalServerError)
	ErrCircuitOpen        = New("circuit_open", "service temporarily unavailable", http.StatusServiceUnavailable)
)

// AppError is a structured error that carries an HTTP status, error code,
// human-readable message, and optional wrapped cause.
type AppError struct {
	Code       string
	Message    string
	HTTPStatus int
	cause      error
	fields     map[string]interface{}
}

func New(code, message string, status int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		fields:     make(map[string]interface{}),
	}
}

func (e *AppError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.cause
}

// Wrap returns a new AppError with a causal chain.
func (e *AppError) Wrap(cause error) *AppError {
	return &AppError{
		Code:       e.Code,
		Message:    e.Message,
		HTTPStatus: e.HTTPStatus,
		cause:      cause,
		fields:     e.fields,
	}
}

// WithField returns a new AppError with additional context fields for logging.
func (e *AppError) WithField(key string, value interface{}) *AppError {
	fields := make(map[string]interface{}, len(e.fields)+1)
	for k, v := range e.fields {
		fields[k] = v
	}
	fields[key] = value
	return &AppError{
		Code:       e.Code,
		Message:    e.Message,
		HTTPStatus: e.HTTPStatus,
		cause:      e.cause,
		fields:     fields,
	}
}

func (e *AppError) Fields() map[string]interface{} {
	return e.fields
}

// Is enables errors.Is matching against the Code field.
func (e *AppError) Is(target error) bool {
	var t *AppError
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// AsAppError extracts an AppError from the error chain, returning a generic
// 500 error if none is found.
func AsAppError(err error) *AppError {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae
	}
	return ErrInternalServer.Wrap(err)
}

// IsNotFound returns true if the error chain contains ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsRateLimited returns true if the error chain contains ErrRateLimited.
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// IsComplianceBlock returns true if the action was compliance-blocked.
func IsComplianceBlock(err error) bool {
	return errors.Is(err, ErrComplianceBlock)
}
