package scanner

import "context"

type Resource struct {
	Type string
	ID   string
	ARN  string
}

type AuditRule struct {
	TargetKey string
	TargetVal string
}

type Scanner interface {
	Scan(ctx context.Context, rule AuditRule) ([]Resource, error)
}

func IsCompliant(tags map[string]string, rule AuditRule) bool {
	val, ok := tags[rule.TargetKey]
	return ok && val == rule.TargetVal
}
