package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func NewEC2(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}

func NewECS(cfg aws.Config) *ecs.Client {
	return ecs.NewFromConfig(cfg)
}

func NewLambda(cfg aws.Config) *lambda.Client {
	return lambda.NewFromConfig(cfg)
}
