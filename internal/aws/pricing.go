package aws

import (
	"strings"
)

const (
	CostUnattachedEIP     = 3.65
	CostPublicIPv4        = 3.65
	CostIdleNAT           = 32.85
	CostNATProcessing     = 0.045
	CostVPCEndpoint       = 7.30
	CostVPCEndpointGW     = 0.00
	CostTransitGatewayAtt = 36.50
	CostVPNConnection     = 36.50
	CostClientVPN         = 73.00
	CostGlobalAccelerator = 18.25

	CostALB = 16.42
	CostNLB = 16.42
	CostCLB = 18.25

	CostDynamoWCU          = 0.47
	CostDynamoRCU          = 0.09
	CostDynamoStorage      = 0.25
	CostRedshiftRA3XL      = 792.78
	CostRedshiftDC2Large   = 182.50
	CostRedshiftRMS        = 0.024
	CostRedshiftServerless = 0.36
	CostRDSStorageGP3      = 0.115
	CostRDSStorageAurora   = 0.10

	CostCacheT3Micro  = 12.41
	CostCacheT3Small  = 24.82
	CostCacheM5Large  = 106.58
	CostValkeyT3Micro = 9.93
	CostValkeyT3Small = 19.86
	CostMemoryDBMicro = 35.00

	CostEKSCluster = 73.00
	CostECSCluster = 0.00

	CostLambdaProv    = 0.0000041667
	CostGlueCrawler   = 0.44
	CostStepFuncState = 0.000025

	CostEBSGP3       = 0.08
	CostEBSIO2       = 0.125
	CostSnapshot     = 0.05
	CostS3Standard   = 0.023
	CostKinesisShard = 10.95

	CostSageMakerT3Med = 36.50
	CostSageMakerM5Lg  = 160.60

	CostKMSKey    = 1.00
	CostSecret    = 0.40
	CostWAFWebACL = 5.00
)

var InstancePrices = map[string]float64{
	"t2.micro": 8.47, "t3.micro": 7.61, "t3.small": 15.21, "t3.medium": 30.43,
	"m5.large": 70.08, "c5.large": 62.05, "r5.large": 91.98,
	"db.t3.micro": 12.00, "db.t3.small": 24.00, "db.m5.large": 100.00,
	"ra3.xlplus": 792.78, "dc2.large": 182.50,
	"ml.t3.medium": 36.50, "ml.m5.large": 160.60,
}

func EstimateCost(serviceType string, instanceType string, metric float64) float64 {
	svc := strings.ToLower(serviceType)
	iType := strings.ToLower(instanceType)

	if strings.Contains(svc, "dynamodb") {
		if strings.Contains(iType, "write") || strings.Contains(iType, "wcu") {
			return metric * CostDynamoWCU
		}
		if strings.Contains(iType, "read") || strings.Contains(iType, "rcu") {
			return metric * CostDynamoRCU
		}
		if strings.Contains(iType, "storage") {
			return metric * CostDynamoStorage
		}
		return 0
	}

	if strings.Contains(svc, "kinesis") {
		if metric <= 0 {
			metric = 1
		}
		return metric * CostKinesisShard
	}

	if strings.Contains(svc, "redshift") {
		if val, ok := InstancePrices[iType]; ok {
			return val
		}
		if strings.Contains(iType, "serverless") {
			return 100.00
		}
		return CostRedshiftDC2Large
	}

	if strings.Contains(svc, "sagemaker") || strings.Contains(svc, "notebook") {
		if strings.Contains(iType, "medium") {
			return CostSageMakerT3Med
		}
		if strings.Contains(iType, "large") {
			return CostSageMakerM5Lg
		}
		return CostSageMakerT3Med
	}

	if strings.Contains(svc, "glue") || strings.Contains(svc, "crawler") {
		if metric <= 0 {
			return 0
		}
		return metric * 2 * CostGlueCrawler
	}

	if strings.Contains(svc, "lambda") && strings.Contains(iType, "provisioned") {
		return metric * CostLambdaProv
	}

	if strings.Contains(svc, "elasticache") || strings.Contains(svc, "valkey") {
		if strings.Contains(svc, "valkey") {
			if strings.Contains(iType, "micro") {
				return CostValkeyT3Micro
			}
			if strings.Contains(iType, "small") {
				return CostValkeyT3Small
			}
		}
		if strings.Contains(iType, "micro") {
			return CostCacheT3Micro
		}
		if strings.Contains(iType, "small") {
			return CostCacheT3Small
		}
		if strings.Contains(iType, "large") {
			return CostCacheM5Large
		}
		return CostCacheT3Micro
	}

	if strings.Contains(svc, "waf") || strings.Contains(svc, "acl") {
		return CostWAFWebACL
	}

	if strings.Contains(svc, "transit") || strings.Contains(svc, "tgw") {
		return CostTransitGatewayAtt
	}

	if strings.Contains(svc, "accelerator") {
		return CostGlobalAccelerator
	}

	if strings.Contains(svc, "nat") {
		return CostIdleNAT
	}
	if strings.Contains(svc, "eks") {
		return CostEKSCluster
	}
	if strings.Contains(svc, "kms") {
		return CostKMSKey
	}
	if strings.Contains(svc, "secret") {
		return CostSecret
	}
	if strings.Contains(svc, "public ip") {
		return CostPublicIPv4
	}
	if strings.Contains(svc, "elastic ip") {
		return CostUnattachedEIP
	}

	if strings.Contains(svc, "ec2") {
		if val, ok := InstancePrices[iType]; ok {
			return val
		}
		return 30.00
	}

	if strings.Contains(svc, "ebs") {
		if metric <= 0 {
			metric = 20
		}
		return metric * CostEBSGP3
	}

	if strings.Contains(svc, "rds") {
		cost := 0.0
		if val, ok := InstancePrices[iType]; ok {
			cost = val
		} else {
			cost = 25.00
		}
		if metric > 0 {
			if strings.Contains(iType, "aurora") {
				cost += metric * CostRDSStorageAurora
			} else {
				cost += metric * CostRDSStorageGP3
			}
		}
		return cost
	}

	return 0.0
}
