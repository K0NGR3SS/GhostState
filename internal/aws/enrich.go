package aws

import (
	"strings"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func appendUniqueRefs(existing []string, refs ...string) []string {
	seen := make(map[string]bool, len(existing)+len(refs))
	var result []string
	for _, ref := range existing {
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		result = append(result, ref)
	}
	for _, ref := range refs {
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		result = append(result, ref)
	}
	return result
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// EnrichResource adds v1.4 action metadata after service scanners return.
func EnrichResource(r scanner.Resource) scanner.Resource {
	service := strings.ToLower(r.Service + " " + r.Type)
	details := strings.ToLower(r.RiskInfo + " " + r.GhostInfo)

	if r.Recommendation == "" {
		switch {
		case r.Risk == "UNKNOWN":
			r.Recommendation = "Review scan errors and grant the required read permissions, then rerun the unavailable checks."
		case containsAny(service, "security group") && containsAny(details, "open to world"):
			r.Recommendation = "Restrict inbound rules to trusted CIDRs, remove unused wide-open rules, or move access behind a VPN/bastion."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub EC2.19", "AWS Config restricted-ssh")
		case containsAny(service, "s3") && containsAny(details, "public"):
			r.Recommendation = "Enable full S3 Block Public Access unless this bucket is intentionally public and has documented controls."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub S3.8", "AWS Config s3-bucket-public-read-prohibited")
		case containsAny(service, "s3") && containsAny(details, "encryption"):
			r.Recommendation = "Enable default server-side encryption for the bucket."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub S3.5", "AWS Config s3-bucket-server-side-encryption-enabled")
		case containsAny(service, "s3") && containsAny(details, "versioning"):
			r.Recommendation = "Enable bucket versioning for recoverability and change protection."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub S3.14")
		case containsAny(service, "rds") && containsAny(details, "public"):
			r.Recommendation = "Disable public accessibility and require private network paths for database clients."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub RDS.2")
		case containsAny(service, "rds") && containsAny(details, "unencrypted"):
			r.Recommendation = "Migrate or restore the database with storage encryption enabled."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub RDS.3", "AWS Config rds-storage-encrypted")
		case containsAny(service, "rds") && containsAny(details, "backups"):
			r.Recommendation = "Enable automated backups with a retention period that matches recovery requirements."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub RDS.9", "AWS Config db-instance-backup-enabled")
		case containsAny(service, "rds") && containsAny(details, "deletion protection"):
			r.Recommendation = "Enable deletion protection for production databases or document why deletion is intentionally allowed."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub RDS.8")
		case containsAny(service, "cloudtrail") && containsAny(details, "stopped"):
			r.Recommendation = "Re-enable CloudTrail logging and confirm management events are captured."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub CloudTrail.1", "SecurityHub CloudTrail.3")
		case containsAny(service, "cloudtrail") && containsAny(details, "validation"):
			r.Recommendation = "Enable CloudTrail log file validation to detect tampering."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub CloudTrail.4")
		case containsAny(service, "ec2") && containsAny(details, "public ip"):
			r.Recommendation = "Remove direct public exposure where possible and place access behind a load balancer, VPN, or private connectivity."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub EC2.9")
		case containsAny(service, "ec2") && containsAny(details, "imdsv2"):
			r.Recommendation = "Require IMDSv2 by setting instance metadata tokens to required."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub EC2.8")
		case containsAny(service, "lambda") && containsAny(details, "runtime"):
			r.Recommendation = "Upgrade the function runtime to a currently supported runtime and redeploy."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub Lambda.2")
		case containsAny(service, "lambda") && containsAny(details, "public function url"):
			r.Recommendation = "Require AWS_IAM authentication for the Function URL or remove the URL if it is not intentionally public."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub Lambda.1")
		case containsAny(service, "ecr") && containsAny(details, "scanning"):
			r.Recommendation = "Enable image scanning on push or enhanced scanning for the repository."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ECR.1")
		case containsAny(service, "ecr") && containsAny(details, "lifecycle"):
			r.Recommendation = "Add an ECR lifecycle policy to expire stale images and reduce repository sprawl."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ECR.3")
		case containsAny(service, "ecr") && containsAny(details, "mutable"):
			r.Recommendation = "Use immutable tags for release images or document repositories that intentionally allow mutable tags."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ECR.2")
		case containsAny(service, "ebs") && containsAny(details, "unencrypted"):
			r.Recommendation = "Create an encrypted copy or snapshot and replace the unencrypted volume."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub EC2.3", "AWS Config encrypted-volumes")
		case containsAny(service, "ebs") && containsAny(details, "gp2"):
			r.Recommendation = "Evaluate migration from gp2 to gp3 to reduce storage cost while preserving required performance."
		case containsAny(service, "acm") && containsAny(details, "expires"):
			r.Recommendation = "Renew or replace the certificate before expiry and confirm dependent listeners are updated."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ACM.1")
		case containsAny(service, "load balancer", "elb") && containsAny(details, "access logging"):
			r.Recommendation = "Enable load balancer access logging to S3 for investigation and traffic auditability."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ELB.5")
		case containsAny(service, "load balancer", "elb") && containsAny(details, "https", "tls"):
			r.Recommendation = "Add an HTTPS/TLS listener and redirect plaintext traffic where possible."
			r.ControlRefs = appendUniqueRefs(r.ControlRefs, "SecurityHub ELB.1")
		case r.IsGhost:
			r.Recommendation = "Confirm ownership, then remove or right-size the unused resource to reduce drift and monthly spend."
		case r.Risk != "" && r.Risk != "SAFE":
			r.Recommendation = "Review the finding, confirm business intent, and remediate or document an exception."
		}
	}

	if r.SavingsEstimate == 0 {
		switch {
		case r.IsGhost && r.MonthlyCost > 0:
			r.SavingsEstimate = r.MonthlyCost
		case containsAny(service, "ebs") && containsAny(r.Type, "gp2") && r.Size > 0:
			r.SavingsEstimate = r.Size * (CostEBSGP2 - CostEBSGP3)
		}
	}

	return r
}
