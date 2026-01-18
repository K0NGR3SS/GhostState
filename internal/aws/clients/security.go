package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func NewACM(cfg aws.Config) *acm.Client {
	return acm.NewFromConfig(cfg)
}

func NewSecurityGroup(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}
