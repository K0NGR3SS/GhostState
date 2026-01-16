package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	tea "github.com/charmbracelet/bubbletea"
)

func scanECS(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := ecs.NewFromConfig(cfg)

	listOut, err := client.ListClusters(context.TODO(), &ecs.ListClustersInput{})
	if err != nil {
		send(p, "ECS: error listing clusters: "+err.Error())
		return
	}

	if len(listOut.ClusterArns) == 0 {
		return
	}

	descOut, err := client.DescribeClusters(context.TODO(), &ecs.DescribeClustersInput{
		Clusters: listOut.ClusterArns,
		Include:  []types.ClusterField{types.ClusterFieldTags},
	})
	if err != nil {
		return
	}

	for _, cl := range descOut.Clusters {
		name := aws.ToString(cl.ClusterName)
		status := aws.ToString(cl.Status)

		hasTag := false
		for _, t := range cl.Tags {
			if t.Key != nil && t.Value != nil &&
				*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
				hasTag = true
				break
			}
		}

		if !hasTag {
			send(p, fmt.Sprintf("ECS: cluster=%s status=%s", name, status))
		}
	}
}
