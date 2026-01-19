package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func NewACM(cfg aws.Config) *acm.Client {
	return acm.NewFromConfig(cfg)
}

func NewSecurityGroup(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}

func NewIAM(cfg aws.Config) *iam.Client {
	return iam.NewFromConfig(cfg)
}

func NewSecretsManager(cfg aws.Config) *secretsmanager.Client {
	return secretsmanager.NewFromConfig(cfg)
}

func NewKMS(cfg aws.Config) *kms.Client {
	return kms.NewFromConfig(cfg)
}

func NewCloudTrail(cfg aws.Config) *cloudtrail.Client {
	return cloudtrail.NewFromConfig(cfg)
}
