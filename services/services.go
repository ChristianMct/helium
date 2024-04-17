// Package services provides common utilities for services.
package services

import "context"

type ctxKeyT string

const (
	CtxKeyName ctxKeyT = "service"
)

// ServiceFromContext returns the service name from the context.
func ServiceFromContext(ctx context.Context) (string, bool) {
	service, ok := ctx.Value(CtxKeyName).(string)
	return service, ok
}
