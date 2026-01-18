package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func NewS3(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg)
}

func NewRDS(cfg aws.Config) *rds.Client {
	return rds.NewFromConfig(cfg)
}

func NewDynamoDB(cfg aws.Config) *dynamodb.Client {
	return dynamodb.NewFromConfig(cfg)
}

func NewElastiCache(cfg aws.Config) *elasticache.Client {
	return elasticache.NewFromConfig(cfg)
}
