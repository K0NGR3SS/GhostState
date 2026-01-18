# GhostState (v1.1)

![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)
![AWS](https://img.shields.io/badge/AWS-SDK_v2-232F3E?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

GhostState is a CLI tool built in Go for AWS cloud governance. It scans your infrastructure to identify "drift" or "shadow IT" resources that are missing specific governance tags.

It features a robust, hexagonal architecture and a real-time, terminal-based dashboard (TUI) that categorizes resources as **Ghosts** (👻) if they fail compliance checks.

## Features

*   **Interactive TUI:** Beautiful Bubble Tea interface with granular resource selection.
*   **Multi-Tag Compliance:** Support for complex audit rules. Input comma-separated keys and values (e.g., `ManagedBy,Env` -> `Terraform,Prod`) to enforce multiple tags at once.
*   **Categorized Reporting:** Results are intelligent grouped by domain (Computing, Data, Networking/Security).
*   **Performance Metrics:** Tracks and displays exact scan duration.
*   **Clean Architecture:** Built using the Provider pattern with separated Clients and Scanners for high maintainability.

## Supported Services

GhostState currently audits the following AWS resources:

### Computing
*   **EC2** Instances
*   **ECS** Clusters
*   **Lambda** Functions

### Data & Storage
*   **S3** Buckets
*   **RDS** Databases
*   **DynamoDB** Tables
*   **ElastiCache** Clusters

### Networking & Security
*   **VPC Stack** (VPC, Subnets, Internet Gateways, NAT Gateways)
*   **CloudFront** Distributions
*   **ACM** Certificates
*   **Security Groups**

## Usage

**Prerequisites**
*   Go 1.23+
*   Configured AWS Credentials (`~/.aws/credentials` or environment variables)

**Run from Source**

```bash
git clone https://github.com/K0NGR3SS/GhostState.git
cd GhostState
go mod tidy
go run cmd/ghoststate/main.go
