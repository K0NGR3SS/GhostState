package clients

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2" //(FOR EIP)
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	
)

func NewCloudFront(cfg aws.Config) *cloudfront.Client {
	return cloudfront.NewFromConfig(cfg)
}

func NewVPC(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}

func NewELB(cfg aws.Config) *elasticloadbalancingv2.Client {
    return elasticloadbalancingv2.NewFromConfig(cfg)
}
func NewRoute53(cfg aws.Config) *route53.Client {
	return route53.NewFromConfig(cfg)
}
