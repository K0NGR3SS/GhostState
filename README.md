# GhostState (v1.2)

![Status](https://img.shields.io/badge/status-building-blue)
![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)
![AWS](https://img.shields.io/badge/AWS-SDK_v2-232F3E?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

GhostState is a CLI security and governance tool for AWS. It scans your infrastructure to identify "Ghost" resources (shadow IT/unused assets) and "Risk" resources (security vulnerabilities) in real-time.

It features a robust, hexagonal architecture and a terminal-based dashboard (TUI) that provides instant visibility into your cloud posture.

## New Features

GhostState has been upgraded with a powerful **Risk Analysis Engine** and **Safety Checks** to go beyond simple inventory scanning:

*   **Risk Analysis Engine:** Automatically detects critical security flaws such as open SSH ports, public S3 buckets, unencrypted databases, and stale IAM credentials.
*   **Smart Scan Modes:**
    *   **ALL:** Displays the full infrastructure inventory.
    *   **RISK:** Filters purely for **Critical** (💀), **High** (🚨), and **Medium** (⚠️) security issues.
    *   **GHOST:** Filters for unused or "shadow" resources (e.g., unattached IPs, empty clusters).
*   **Tag Compliance:** Now enforces governance by filtering resources missing specific tags (e.g., `ManagedBy: Terraform`), helping you spot drift immediately.
*   **Safety Categorization:** Results are visually categorized by risk level, making it easy to prioritize remediation.

## Risk & Safety Checks

GhostState performs the following audits during every scan:

| Service | Risk Check |
| :--- | :--- |
| **EC2** | Public IP detection, Stopped instances (Ghost) |
| **S3** | **Public Access** detection (High Risk) |
| **IAM** | **Stale Passwords** (>90 days), No Console Login (Ghost) |
| **Security Groups** | **SSH (22) / RDP (3389)** Open to World (Critical) |
| **RDS** | **Public Access**, Storage Encryption Disabled |
| **DynamoDB** | Point-In-Time Recovery (Backups) Disabled |
| **EBS** | Unencrypted Volumes, Unattached Volumes (Ghost) |
| **CloudFront** | WAF Disabled, Distribution Disabled (Ghost) |
| **Lambda** | Deprecated Runtimes (e.g., Python 3.7) |
| **ELB/ALB** | Internet Facing detection |
| **CloudTrail** | Logging Disabled (Critical), Validation Disabled |

## Supported Services

GhostState audits the following AWS resources:

### Computing
*   **EC2** Instances
*   **ECS** Clusters
*   **Lambda** Functions
*   **EKS** Clusters
*   **ECR** Repositories

### Data & Storage
*   **S3** Buckets
*   **RDS** Databases
*   **DynamoDB** Tables
*   **ElastiCache** Clusters
*   **EBS** Volumes

### Networking
*   **VPC Stack** (VPC, Subnets, IGW)
*   **CloudFront** Distributions
*   **Elastic IPs** (EIP)
*   **Load Balancers** (ELB/ALB)
*   **Route53** Hosted Zones

### Security & Identity
*   **Security Groups**
*   **ACM** Certificates
*   **IAM** Users
*   **KMS** Keys
*   **Secrets Manager** Secrets
*   **CloudTrail** Trails

### Monitoring
*   **CloudWatch** Alarms

## Usage

**Prerequisites**
*   Go 1.25+
*   Configured AWS Credentials (`~/.aws/credentials` or environment variables)

**Run from Source**

```bash
git clone https://github.com/K0NGR3SS/GhostState.git
cd GhostState
go mod tidy
go run cmd/ghoststate/main.go
