package scanner

import "context"

type Resource struct {
	Type string
	ID   string
	ARN  string
	Tags map[string]string
	Risk     string
	RiskInfo string
	IsGhost   bool
	GhostInfo string

	Info string
}

type AuditRule struct {
	Tags      map[string]string
	TargetKey string
	TargetVal string
	ScanMode  string
}

type AuditConfig struct {
	ScanEC2, ScanS3, ScanRDS, ScanElasti     bool
	ScanACM, ScanSecGroups, ScanECS          bool
	ScanCloudfront, ScanLambda, ScanDynamoDB bool
	ScanVPC                                  bool

	ScanEBS, ScanIAM, ScanSecrets, ScanCloudWatch bool
	ScanEIP, ScanELB, ScanECR, ScanEKS, ScanKMS   bool

	TargetRule AuditRule
}

type Scanner interface {
	Scan(ctx context.Context, rule AuditRule) ([]Resource, error)
}

func IsCompliant(resourceTags map[string]string, rule AuditRule) bool {
	if len(rule.Tags) == 0 && rule.TargetKey == "" {
		return true
	}

	if len(rule.Tags) > 0 {
		for key, requiredVal := range rule.Tags {
			val, ok := resourceTags[key]
			if !ok || val != requiredVal {
				return false
			}
		}
	}

	if rule.TargetKey != "" {
		val, ok := resourceTags[rule.TargetKey]
		if !ok {
			return false
		}
		if rule.TargetVal != "" && val != rule.TargetVal {
			return false
		}
	}

	return true
}

func MatchesRule(tags map[string]string, rule AuditRule) bool {
	return IsCompliant(tags, rule)
}
