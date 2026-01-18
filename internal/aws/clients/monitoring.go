package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

func NewCloudWatch(cfg aws.Config) *cloudwatch.Client {
	return cloudwatch.NewFromConfig(cfg)
}
