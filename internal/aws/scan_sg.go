package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	tea "github.com/charmbracelet/bubbletea"
)

func scanSecGroups(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := ec2.NewFromConfig(cfg)

	out, err := client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		send(p, "SG: error listing security groups: "+err.Error())
		return
	}

	for _, sg := range out.SecurityGroups {
		id := aws.ToString(sg.GroupId)
		name := aws.ToString(sg.GroupName)
		vpc := aws.ToString(sg.VpcId)

		send(p, fmt.Sprintf("SG: id=%s name=%s vpc=%s", id, name, vpc))
	}
}
