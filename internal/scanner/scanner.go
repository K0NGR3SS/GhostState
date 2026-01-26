package scanner

import "context"

type Resource struct {
	Type      string
	ID        string
	ARN       string
	
	// Fields for pricing and metadata
	Service   string 
	Status    string
	Size      float64
	Region    string  // NEW: Track which region resource is in
	
	Risk      string
	RiskInfo  string
	GhostInfo string
	Info      string

	Tags map[string]string

	IsGhost     bool
	MonthlyCost float64
}

type AuditRule struct {
	Tags      map[string]string
	TargetKey string
	TargetVal string
	ScanMode  string
}

type AuditConfig struct {
	TargetRule AuditRule
	Regions    []string  // List of regions to scan (empty = current region only)

	ScanEC2    bool
	ScanECS    bool
	ScanLambda bool
	ScanEKS    bool
	ScanECR    bool

	ScanS3       bool
	ScanRDS      bool
	ScanDynamoDB bool
	ScanElasti   bool
	ScanEBS      bool

	ScanVPC        bool
	ScanCloudfront bool
	ScanEIP        bool
	ScanELB        bool
	ScanRoute53    bool

	ScanACM        bool
	ScanSecGroups  bool
	ScanIAM        bool
	ScanSecrets    bool
	ScanKMS        bool
	ScanCloudTrail bool

	ScanCloudWatch bool
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