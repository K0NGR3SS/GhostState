package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	tea "github.com/charmbracelet/bubbletea"
)

func scanRDS(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := rds.NewFromConfig(cfg)

	instOut, err := client.DescribeDBInstances(context.TODO(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		send(p, "RDS: error describing DB instances: "+err.Error())
	} else {
		for _, db := range instOut.DBInstances {
			id := aws.ToString(db.DBInstanceIdentifier)
			engine := aws.ToString(db.Engine)
			engineVer := aws.ToString(db.EngineVersion)
			public := db.PubliclyAccessible
			enc := db.StorageEncrypted
			backupWindow := aws.ToString(db.PreferredBackupWindow)

			hasTag := false
			tagOut, err := client.ListTagsForResource(context.TODO(), &rds.ListTagsForResourceInput{
				ResourceName: db.DBInstanceArn,
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

			if !hasTag {
				send(p, fmt.Sprintf(
					"RDS: instance=%s engine=%s(%s) public=%t encrypted=%t backupWindow=%s",
					id, engine, engineVer, public, enc, backupWindow,
				))
			}
		}
	}

	clOut, err := client.DescribeDBClusters(context.TODO(), &rds.DescribeDBClustersInput{})
	if err != nil {
		return
	}

	for _, cl := range clOut.DBClusters {
		id := aws.ToString(cl.DBClusterIdentifier)
		engine := aws.ToString(cl.Engine)
		engineVer := aws.ToString(cl.EngineVersion)
		enc := cl.StorageEncrypted
		backtrack := cl.BacktrackWindow

		hasTag := false
		tagOut, err := client.ListTagsForResource(context.TODO(), &rds.ListTagsForResourceInput{
			ResourceName: cl.DBClusterArn,
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

		if !hasTag {
			send(p, fmt.Sprintf(
				"RDS-Cluster: id=%s engine=%s(%s) encrypted=%t backtrackWindow=%d",
				id, engine, engineVer, enc, backtrack,
			))
		}
	}
}
