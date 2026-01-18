package scanner

import "context"

type Resource struct {
	Type string
	ID   string
	ARN  string
}

type AuditRule struct {
	Tags map[string]string 
}

type AuditConfig struct {
	ScanEC2, ScanS3, ScanRDS, ScanElasti     bool
	ScanACM, ScanSecGroups, ScanECS          bool
	ScanCloudfront, ScanLambda, ScanDynamoDB bool
	ScanVPC                                  bool
	
	TargetRule AuditRule
}

type Scanner interface {
	Scan(ctx context.Context, rule AuditRule) ([]Resource, error)
}

func IsCompliant(resourceTags map[string]string, rule AuditRule) bool {
	if len(rule.Tags) == 0 {
		return true 
	}

	for key, requiredVal := range rule.Tags {
		val, ok := resourceTags[key]
		if !ok || val != requiredVal {
			return false
		}
	}
	return true
}
