# GhostState (v1.0)

![Status](https://img.shields.io/badge/Status-WIP-orange)
![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)
![AWS](https://img.shields.io/badge/AWS-SDK_v2-232F3E?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

GhostState is a CLI tool built in Go for AWS cloud governance. It scans your infrastructure to identify "drift" or "shadow IT" resources that are missing specific governance tags (e.g., `ManagedBy: Terraform`).

It features a real-time, terminal-based dashboard that categorizes resources as **Clean** (🛡️) or **Ghosts** (👻)

## Features

*   **Interactive TUI:** Beautiful Bubble Tea interface with granular resource selection.
*   **Categorized Reporting:** Results are automatically grouped by domain (Computing, Data, Networking) for easier analysis.
*   **Drift Detection:** Scans resources against a user-defined Tag Key/Value pair.
*   **Real-time Feedback:** Live scanning status with visual indicators.

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
*   **VPC Stack** (VPC, Subnets, Internet Gateways)
*   **CloudFront** Distributions
*   **ACM** Certificates
*   **Security Groups**

## Usage

**Prerequisites**
*   Go 1.23+
*   Configured AWS Credentials (`~/.aws/credentials` or environment variables)

**Run**

```bash
git clone https://github.com/K0NGR3SS/GhostState.git
cd GhostState
go mod tidy
go run cmd/ghoststate/main.go
