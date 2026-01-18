package scanner

import "context"

type Resource struct {
	Type string
	ID   string
	ARN  string
	Tags map[string]string
	Risk string
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

// IsCompliant checks if a resource matches the Tag Filters.
func IsCompliant(resourceTags map[string]string, rule AuditRule) bool {
	// 1. If no filters are set, EVERYTHING is compliant.
	if len(rule.Tags) == 0 && rule.TargetKey == "" {
		return true
	}

	// 2. Check the legacy Tags map (if used)
	if len(rule.Tags) > 0 {
		for key, requiredVal := range rule.Tags {
			val, ok := resourceTags[key]
			if !ok || val != requiredVal {
				return false
			}
		}
	}

	// 3. Check the Single Key/Value filter (from UI)
	if rule.TargetKey != "" {
		// Does the resource have this Tag Key?
		val, ok := resourceTags[rule.TargetKey]
		if !ok {
			return false // Key missing -> Hide Resource
		}
		// If a Value is also specified, does it match?
		if rule.TargetVal != "" && val != rule.TargetVal {
			return false // Value mismatch -> Hide Resource
		}
	}

	return true
}

func MatchesRule(tags map[string]string, rule AuditRule) bool {
	return IsCompliant(tags, rule)
}
