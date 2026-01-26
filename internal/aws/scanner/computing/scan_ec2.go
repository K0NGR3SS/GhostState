package computing

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2Scanner struct {
	Client *ec2.Client
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{Client: ec2.NewFromConfig(cfg)}
}

// Helper function to estimate EBS volume cost
func (s *EC2Scanner) estimateEBSCost(ctx context.Context, volumeID *string) float64 {
	if volumeID == nil {
		return 0
	}

	// Fetch volume details
	volOut, err := s.Client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: []string{*volumeID},
	})
	if err != nil || len(volOut.Volumes) == 0 {
		return 0
	}

	vol := volOut.Volumes[0]
	size := float64(0)
	if vol.Size != nil {
		size = float64(*vol.Size)
	}

	// Cost per GB per month based on volume type
	costPerGB := 0.08 // GP3 default
	switch vol.VolumeType {
	case types.VolumeTypeGp2:
		costPerGB = 0.10
	case types.VolumeTypeGp3:
		costPerGB = 0.08
	case types.VolumeTypeIo1, types.VolumeTypeIo2:
		costPerGB = 0.125
	case types.VolumeTypeSc1:
		costPerGB = 0.015
	case types.VolumeTypeSt1:
		costPerGB = 0.045
	case types.VolumeTypeStandard:
		costPerGB = 0.05
	}

	return size * costPerGB
}

// Enhanced EC2 cost calculation
func (s *EC2Scanner) estimateEC2Cost(ctx context.Context, inst types.Instance) float64 {
	baseCost := 0.0

	// Get instance type base cost
	instanceType := string(inst.InstanceType)
	if price, ok := InstancePrices[instanceType]; ok {
		baseCost = price
	} else {
		// Default estimate if instance type not in our pricing map
		baseCost = 30.00
	}

	// If instance is stopped, only count EBS costs (no compute cost)
	if inst.State != nil && inst.State.Name == types.InstanceStateNameStopped {
		baseCost = 0
	}

	// Add EBS volume costs (these apply even if instance is stopped)
	for _, bdm := range inst.BlockDeviceMappings {
		if bdm.Ebs != nil && bdm.Ebs.VolumeId != nil {
			baseCost += s.estimateEBSCost(ctx, bdm.Ebs.VolumeId)
		}
	}

	// Add public IPv4 cost if applicable (charges apply even if stopped)
	if inst.PublicIpAddress != nil {
		baseCost += 3.65
	}

	return baseCost
}

// Import pricing map from parent package
var InstancePrices = map[string]float64{
	"t2.micro": 8.47, "t3.micro": 7.61, "t3.small": 15.21, "t3.medium": 30.43,
	"t3.large": 60.74, "t3.xlarge": 121.47, "t3.2xlarge": 242.93,
	"m5.large": 70.08, "m5.xlarge": 140.16, "m5.2xlarge": 280.32,
	"c5.large": 62.05, "c5.xlarge": 124.10, "c5.2xlarge": 248.20,
	"r5.large": 91.98, "r5.xlarge": 183.96, "r5.2xlarge": 367.92,
	"t4g.micro": 6.13, "t4g.small": 12.26, "t4g.medium": 24.53,
	"m6g.medium": 29.93, "m6g.large": 59.86, "m6g.xlarge": 119.72,
}

func (s *EC2Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := ec2.NewDescribeInstancesPaginator(s.Client, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, r := range out.Reservations {
			for _, inst := range r.Instances {
				stateName := "unknown"
				if inst.State != nil {
					stateName = string(inst.State.Name)
				}

				res := scanner.Resource{
					ID:      aws.ToString(inst.InstanceId),
					Service: "EC2",
					Type:    string(inst.InstanceType),
					Status:  stateName,
					Tags:    map[string]string{},
					Risk:    "SAFE",
				}

				// Extract tags
				for _, t := range inst.Tags {
					if t.Key != nil && t.Value != nil {
						res.Tags[*t.Key] = *t.Value
					}
				}

				// Calculate enhanced cost
				res.MonthlyCost = s.estimateEC2Cost(ctx, inst)

				// Ghost detection: Stopped instances
				if inst.State != nil && inst.State.Name == types.InstanceStateNameStopped {
					res.IsGhost = true
					res.GhostInfo = fmt.Sprintf("Stopped instance (still incurs EBS/IP costs: $%.2f/mo)", res.MonthlyCost)
				}

				// Risk detection: Public IP on running instance
				if inst.State != nil && inst.State.Name == types.InstanceStateNameRunning && inst.PublicIpAddress != nil {
					res.Risk = "HIGH"
					res.RiskInfo = fmt.Sprintf("Public IP: %s", *inst.PublicIpAddress)
				}

				// Apply audit rule filter
				if scanner.MatchesRule(res.Tags, rule) {
					results = append(results, res)
				}
			}
		}
	}

	return results, nil
}