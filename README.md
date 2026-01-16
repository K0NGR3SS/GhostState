# GhostState (v1.0)

![Status](https://img.shields.io/badge/Status-WIP-orange)
![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)
![AWS](https://img.shields.io/badge/AWS-SDK_v2-232F3E?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

GhostState is a CLI tool built in Go for AWS cloud governance. It scans infrastructure to identify "drift" or "shadow IT" resources that are missing specific governance tags.

## Features

*   **Interactive TUI:** Terminal-based interface to select services and configure audit rules.
*   **Drift Detection:** Identifies resources missing a specified Tag Key/Value pair.
*   **Supported Services:**
    *   EC2 Instances
    *   S3 Buckets
    *   RDS Databases
    *   ElastiCache
    *   ACM Certificates
    *   Security Groups
    *   ECS Clusters
    *   CloudFront Distributions

## Usage

**Prerequisites**
*   Go 1.23+
*   Configured AWS Credentials

**Run**

```bash
git clone https://github.com/K0NGR3SS/GhostState.git
cd GhostState
go mod tidy
go run cmd/ghoststate/main.go
