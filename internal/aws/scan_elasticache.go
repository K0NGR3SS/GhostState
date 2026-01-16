package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elc "github.com/aws/aws-sdk-go-v2/service/elasticache"
	tea "github.com/charmbracelet/bubbletea"
)

func scanElasti(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := elc.NewFromConfig(cfg)
	repOut, err := client.DescribeReplicationGroups(context.TODO(), &elc.DescribeReplicationGroupsInput{})
	if err != nil {
		send(p, "ElastiCache: error describing replication groups: "+err.Error())
	} else {
		for _, rg := range repOut.ReplicationGroups {
			id := aws.ToString(rg.ReplicationGroupId)
			engine := aws.ToString(rg.Engine)
			desc := aws.ToString(rg.Description)
			atRest := rg.AtRestEncryptionEnabled
			inTransit := rg.TransitEncryptionEnabled

			hasTag := false
			if rg.ARN != nil {
				tagOut, err := client.ListTagsForResource(context.TODO(), &elc.ListTagsForResourceInput{
					ResourceName: rg.ARN,
				})
				if err == nil {
					for _, t := range tagOut.TagList {
						if t.Key != nil && t.Value != nil &&
							*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
							hasTag = true
							break
						}
					}
				}
			}

			if !hasTag {
				send(p, fmt.Sprintf(
					"ElastiCache-RG: id=%s engine=%s atRestEnc=%t inTransitEnc=%t desc=\"%s\"",
					id, engine, atRest, inTransit, desc,
				))
			}
		}
	}

	clOut, err := client.DescribeCacheClusters(context.TODO(), &elc.DescribeCacheClustersInput{
		ShowCacheNodeInfo: aws.Bool(false),
	})
	if err != nil {
		return
	}

	for _, cl := range clOut.CacheClusters {
		id := aws.ToString(cl.CacheClusterId)
		engine := aws.ToString(cl.Engine)
		nodeType := aws.ToString(cl.CacheNodeType)

		hasTag := false
		if cl.ARN != nil {
			tagOut, err := client.ListTagsForResource(context.TODO(), &elc.ListTagsForResourceInput{
				ResourceName: cl.ARN,
			})
			if err == nil {
				for _, t := range tagOut.TagList {
					if t.Key != nil && t.Value != nil &&
						*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
						hasTag = true
						break
					}
				}
			}
		}

		if !hasTag {
			send(p, fmt.Sprintf(
				"ElastiCache-Cluster: id=%s engine=%s nodeType=%s",
				id, engine, nodeType,
			))
		}
	}
}
