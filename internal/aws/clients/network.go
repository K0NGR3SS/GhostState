package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func NewCloudFront(cfg aws.Config) *cloudfront.Client {
	return cloudfront.NewFromConfig(cfg)
}

func NewVPC(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}
