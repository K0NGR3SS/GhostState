package scanner

import "testing"

func TestIsCompliantWithRequiredTagValue(t *testing.T) {
	rule := AuditRule{TargetKey: "ManagedBy", TargetVal: "Terraform"}

	if !IsCompliant(map[string]string{"ManagedBy": "Terraform"}, rule) {
		t.Fatal("expected matching tag value to be compliant")
	}
	if IsCompliant(map[string]string{"ManagedBy": "Console"}, rule) {
		t.Fatal("expected wrong tag value to be non-compliant")
	}
}

func TestIsCompliantWithMultipleTags(t *testing.T) {
	rule := AuditRule{Tags: map[string]string{"Owner": "Security", "Env": "Prod"}}

	if !IsCompliant(map[string]string{"Owner": "Security", "Env": "Prod", "App": "GhostState"}, rule) {
		t.Fatal("expected all required tags to pass")
	}
	if IsCompliant(map[string]string{"Owner": "Security"}, rule) {
		t.Fatal("expected missing required tag to fail")
	}
}
