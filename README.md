# GhostState (v1.2)

![Status](https://img.shields.io/badge/status-building-blue)
![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
![AWS](https://img.shields.io/badge/AWS-SDK_v2-232F3E?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

> **Last Updated:** January 29, 2026

GhostState is an interactive CLI security, governance, and cost-analysis tool for AWS. It scans your infrastructure to identify "Ghost" resources (shadow IT/unused assets), "Risk" resources (security vulnerabilities), and estimates your monthly cloud spend in real-time.

It features a robust, hexagonal architecture and a terminal-based dashboard (TUI) that provides instant visibility into your cloud posture.

---

## New Features for v1.2

### **Advanced Cost Analysis**
- **Real-time Cost Estimation:** Accurate monthly cost estimates for EC2 (including EBS volumes and public IPs), RDS (with storage), and all major services
- **Cost Drill-Down View:** Dedicated view to sort resources by price and identify top spenders
- **Stopped Instance Tracking:** Shows ongoing costs for stopped EC2 instances (EBS + IP charges)
- **Cost-Aware Scanning:** Auto-save CSV includes per-resource monthly cost breakdowns

### **Enhanced Search & Filtering**
- **Real-time Search:** Press `/` to search across resource IDs, types, regions, tags, and risk levels
- **Smart Filtering:** Instantly filter 1000+ resources without performance degradation
- **Multi-criteria Search:** Search by name, service, region, or any tag key/value

### **Multiple Export Formats**
- **CSV Export** (`S`): Full compliance reports with Service, Status, Size, Monthly Cost
- **JSON Export** (`J`): Machine-readable format for programmatic analysis and CI/CD integration
- **HTML Export** (`H`): Beautiful, styled reports with interactive tables and statistics dashboard

### **Performance & Scalability**
- **Worker Pool Architecture:** Controlled concurrency with 10-worker pools per region
- **Tag Caching:** 5-minute TTL cache reduces redundant API calls by ~60%
- **Streaming Auto-Save:** Toggle with `A` to save results incrementally (press `a` in config screen)
- **Multi-Region Support:** Scan across all AWS regions with proper global service deduplication

### **Expanded Security Checks**
- **27+ Critical Ports:** Now detects MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, and more
- **IPv6 Detection:** Identifies security groups open to `::/0` (often overlooked!)
- **S3 Versioning:** Alerts on buckets without versioning enabled
- **S3 Encryption:** Detects unencrypted S3 buckets
- **S3 Logging:** Warns when access logging is disabled
- **IAM Access Keys:** Tracks key age and alerts on keys >90 days old
- **IAM MFA Status:** Identifies users without MFA enabled
- **EBS Encryption:** Flags unencrypted volumes as HIGH risk
- **GP2 to GP3 Recommendations:** Cost optimization suggestions for outdated volume types

### **UI/UX Improvements**
- **Smart Scrolling:** Viewport handling for large datasets (1000+ resources)
- **Modal Details:** Press `Enter` to view full resource details including region, ARN, tags, and cost breakdown
- **Active Filter Display:** Visual indicator when search filters are active
- **Keyboard Shortcuts:** Comprehensive keyboard navigation (`↑/↓`, `Tab`, `/`, `Enter`, `Esc`)

---

## Features Overview

### Interactive Dashboard (TUI)
- **Live Navigation:** Navigate through audit results using arrow keys (`↑`, `↓`), cycle views (Report/Stats/Cost) with `Tab`, and go back with `Esc`
- **Drill-Down Inspector:** Press `Enter` on any resource to open a **Detail Modal**, viewing raw tags, full ARNs, cost breakdowns, and risk explanations
- **Smart Scan Modes:**
  - **ALL:** Displays the full infrastructure inventory
  - **RISK:** Filters purely for **Critical** (💀), **High** (🚨), and **Medium** (⚠️) security issues
  - **GHOST:** Filters for unused or "shadow" resources (e.g., unattached IPs, empty clusters)

### Security & Governance
- **Risk Analysis Engine:** Automatically detects critical security flaws such as open SSH/database ports, public S3 buckets, unencrypted resources, and stale IAM credentials
- **Tag Compliance:** Enforces governance by filtering resources missing specific tags (e.g., `ManagedBy: Terraform`), helping you spot drift immediately
- **Safety Categorization:** Results are visually categorized by risk level using clear indicators (💀, 🚨, ⚠️, 👻, 🛡️)

### Multi-Format Reporting
- **CSV Export (`S`):** Compliance-ready reports with all resource details
- **JSON Export (`J`):** API-friendly format for automation and tooling
- **HTML Export (`H`):** Executive-ready reports with visual statistics
- **Streaming Auto-Save:** Enable with `A` in config to save results as they're discovered

---

## Risk & Safety Checks

GhostState performs comprehensive audits across your AWS infrastructure:

| Service | Risk Checks |
|---------|-------------|
| **EC2** | Public IP detection, Stopped instances (ongoing costs), Enhanced cost calculation with EBS volumes |
| **S3** | Public Access detection (HIGH), Versioning disabled (MEDIUM), Encryption disabled (MEDIUM), Logging disabled (LOW) |
| **IAM** | Stale Passwords (>90 days), Access Keys >90 days old (HIGH), No MFA enabled (MEDIUM), Multiple access keys (LOW), No Console Login (Ghost) |
| **Security Groups** | **27 Critical Ports** including SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), Elasticsearch (9200-9300), and more. IPv4 and IPv6 detection. |
| **RDS** | Public Access (HIGH), Storage Encryption Disabled (MEDIUM), Multi-AZ cost tracking |
| **DynamoDB** | Point-In-Time Recovery (Backups) Disabled (MEDIUM) |
| **EBS** | Unencrypted Volumes (HIGH), Unattached Volumes (Ghost), GP2 to GP3 upgrade recommendations (LOW) |
| **CloudFront** | WAF Disabled (MEDIUM), Distribution Disabled (Ghost) |
| **Lambda** | Deprecated Runtimes (e.g., Python 3.7, Node 12) (MEDIUM) |
| **ELB/ALB** | Internet Facing detection (LOW) |
| **CloudTrail** | Logging Disabled (CRITICAL), Log Validation Disabled (MEDIUM) |
| **ElastiCache** | Encryption at rest/transit disabled (MEDIUM), Empty clusters (Ghost) |
| **EKS** | Public API endpoint (HIGH), No node groups or Fargate profiles (Ghost) |
| **ECR** | Image scanning disabled (LOW), Empty repositories (Ghost) |
| **VPC** | Default VPC usage (LOW/Ghost) |
| **Route53** | Empty hosted zones (Ghost) |
| **Secrets** | Never accessed or unused >90 days (Ghost) |
| **KMS** | Pending deletion (Ghost), Customer-managed key usage review |

---

## Supported Services

GhostState audits **27 AWS services** across all categories:

### Computing
- **EC2** Instances (with EBS volume cost tracking)
- **ECS** Clusters
- **Lambda** Functions
- **EKS** Clusters
- **ECR** Repositories

### Data & Storage
- **S3** Buckets (with versioning, encryption, logging checks)
- **RDS** Databases (with storage cost calculation)
- **DynamoDB** Tables
- **ElastiCache** Clusters
- **EBS** Volumes (with encryption and type optimization)

### Networking
- **VPC** Stack (VPC, Subnets, IGW)
- **CloudFront** Distributions
- **Elastic IPs** (EIP) - with usage tracking
- **Load Balancers** (ELB/ALB/NLB)
- **Route53** Hosted Zones

### Security & Identity
- **Security Groups** (27+ port checks)
- **ACM** Certificates
- **IAM** Users (with access key age and MFA tracking)
- **KMS** Keys
- **Secrets Manager** Secrets
- **CloudTrail** Trails

### Monitoring
- **CloudWatch** Alarms

---

## Usage

**Prerequisites**
*   Go 1.24+
*   Configured AWS Credentials (`~/.aws/credentials` or environment variables)

**Run from Source**

```bash
git clone https://github.com/K0NGR3SS/GhostState.git
cd GhostState
go mod tidy
go run cmd/ghoststate/main.go
