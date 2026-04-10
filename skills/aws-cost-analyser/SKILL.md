---
name: aws-cost-analyser
description: >
  Analyze AWS costs in depth using Cost Explorer. Triggers on: AWS cost breakdown,
  billing analysis, spending by service/tag/account, EC2-Other costs, usage type
  breakdown, multi-account costs, cost trends, tag-based cost allocation, AWS bill,
  cloud spending, cost optimization, reserved instance costs, savings plans costs.
---

# AWS Cost Analyser

Analyze AWS costs interactively using the Cost Explorer API. Supports drill-down by service, usage type, tags, linked accounts, and time periods.

## Safety — READ ONLY

This skill is strictly read-only. NEVER create, modify, or delete any AWS resources. Only use `get-*`, `describe-*`, and `list-*` API calls. If the user asks to take action (e.g., "delete that service", "stop that instance"), explain the finding and recommend the action but do NOT execute it.

## When to Activate

- User asks about AWS costs, billing, or spending
- Questions about specific service costs (EC2, S3, RDS, etc.)
- "EC2-Other" or "what's in EC2 Other" questions
- Tag-based cost allocation or chargeback analysis
- Multi-account / consolidated billing breakdown
- Cost trend analysis or spike investigation
- Questions about VPC costs, NAT Gateway costs, data transfer costs

## Prerequisites

Before running any cost query, verify AWS access:

```bash
aws sts get-caller-identity --output json
```

If this fails, tell the user to configure AWS credentials (`aws configure` or set `AWS_PROFILE`).

Check if this is a management/payer account (enables multi-account analysis):

```bash
aws organizations describe-organization --output json 2>/dev/null
```

If this succeeds, multi-account cost breakdown is available.

**Default date range**: Use first day of current month to today unless the user specifies otherwise. For comparisons, use the equivalent prior period.

## Core Workflows

### 1. Cost Summary by Service

The starting point for most cost analysis. Shows top spending services.

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --output json
```

Parse the JSON response. Each group in `ResultsByTime[].Groups[]` has:
- `Keys[0]` — service name
- `Metrics.UnblendedCost.Amount` — cost as string, convert to float

Sort by cost descending. Present as a markdown table with columns: Service, Cost, % of Total.

### 2. Drill Down by Usage Type (EC2-Other, VPC, etc.)

Essential for understanding composite billing categories. Filter to a specific service and group by `USAGE_TYPE`.

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=USAGE_TYPE \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["SERVICE_NAME"]}}' \
  --output json
```

Common service names to use in the filter (discover exact names with Workflow 6):
- `EC2 - Other` — EBS, NAT Gateway, Data Transfer, Elastic IPs, VPC
- `Amazon Elastic Compute Cloud - Compute` — EC2 instances
- `Amazon Simple Storage Service` — S3
- `Amazon Relational Database Service` — RDS
- `Amazon Virtual Private Cloud` — VPC-specific charges
- `AWS Key Management Service` — KMS

To further narrow, add a usage type filter:

```bash
--filter '{"And":[{"Dimensions":{"Key":"SERVICE","Values":["EC2 - Other"]}},{"Dimensions":{"Key":"USAGE_TYPE","Values":["NatGateway"],"MatchOptions":["CONTAINS"]}}]}'
```

### 3. Tag-Based Cost Analysis

First, discover available cost allocation tags:

```bash
aws ce get-tags \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --output json
```

This returns `Tags[]` — a list of active tag keys. If empty, tell the user that cost allocation tags need to be activated in the AWS Billing console.

Then query costs grouped by a tag:

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=TAG,Key=TAG_KEY \
  --output json
```

For tag + service breakdown (uses both GroupBy slots):

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=TAG,Key=TAG_KEY Type=DIMENSION,Key=SERVICE \
  --output json
```

To filter to a specific tag value:

```bash
--filter '{"Tags":{"Key":"Environment","Values":["production"]}}'
```

### 4. Multi-Account Breakdown (Management Account Only)

Get per-account costs:

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=LINKED_ACCOUNT \
  --output json
```

To get account names alongside IDs:

```bash
aws organizations list-accounts --output json
```

Map account IDs from cost data to account names for display.

For per-account per-service breakdown (uses both GroupBy slots):

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=LINKED_ACCOUNT Type=DIMENSION,Key=SERVICE \
  --output json
```

To filter to specific accounts:

```bash
--filter '{"Dimensions":{"Key":"LINKED_ACCOUNT","Values":["123456789012","987654321098"]}}'
```

### 5. Cost Trends

Daily trends for spike detection:

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity DAILY \
  --metrics UnblendedCost \
  --output json
```

Monthly trends for period comparison:

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --output json
```

When comparing periods, calculate:
- Absolute change: `current - previous`
- Percentage change: `((current - previous) / previous) * 100`
- Use arrows: cost increased, cost decreased, ~ no significant change

### 6. Dimension Discovery

Discover valid values before filtering. Avoids wrong service names.

```bash
aws ce get-dimension-values \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --dimension SERVICE \
  --output json
```

Available dimensions: `SERVICE`, `LINKED_ACCOUNT`, `REGION`, `USAGE_TYPE`, `OPERATION`, `PURCHASE_TYPE`, `INSTANCE_TYPE`, `PLATFORM`, `AZ`, `TENANCY`.

To search within a dimension:

```bash
aws ce get-dimension-values \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --dimension USAGE_TYPE \
  --search-string "NatGateway" \
  --output json
```

## Domain Knowledge

### GroupBy Limit
The Cost Explorer API allows **max 2 GroupBy** dimensions per call. If you need 3 dimensions (e.g., account + service + usage type), make multiple calls: first group by account + service, then for specific accounts drill into service + usage type.

### Service Name Gotchas
Service names in Cost Explorer are NOT the same as common names. Always use Workflow 6 to discover exact names. Common mappings:

| Common Name | Cost Explorer Service Name |
|---|---|
| EC2 instances | Amazon Elastic Compute Cloud - Compute |
| EC2 other (EBS, NAT, etc.) | EC2 - Other |
| S3 | Amazon Simple Storage Service |
| RDS | Amazon Relational Database Service |
| Lambda | AWS Lambda |
| CloudFront | Amazon CloudFront |
| DynamoDB | Amazon DynamoDB |
| ECS/Fargate | Amazon Elastic Container Service |
| VPC | Amazon Virtual Private Cloud |
| Route 53 | Amazon Route 53 |
| CloudWatch | AmazonCloudWatch |
| KMS | AWS Key Management Service |

### EC2-Other Breakdown Map
"EC2 - Other" is a composite category. Group by USAGE_TYPE to see these sub-categories:

| Usage Type Contains | Sub-Category | What It Is |
|---|---|---|
| `NatGateway` | NAT Gateway | Hourly charges + data processing |
| `EBS:VolumeUsage` | EBS Volumes | GP2/GP3/IO1/IO2 storage per GB-month |
| `EBS:SnapshotUsage` | EBS Snapshots | Snapshot storage per GB-month |
| `DataTransfer` | Data Transfer | Cross-AZ, cross-region, internet egress |
| `ElasticIP:IdleAddress` | Elastic IPs | Idle (unattached) EIP charges |
| `VPCPeering` | VPC Peering | Data transfer over peering connections |
| `PublicIPv4` | Public IPv4 | Public IPv4 address charges ($0.005/hr) |
| `LoadBalancerUsage` | Load Balancers | ALB/NLB/CLB hourly + LCU charges |
| `Endpoint` | VPC Endpoints | Interface endpoint hourly charges |
| `TransitGateway` | Transit Gateway | Attachment + data processing |

### VPC Cost Deep Dive
When the user asks about VPC costs, check BOTH:
1. `EC2 - Other` filtered by VPC-related usage types (NAT Gateway, VPC Peering, Endpoints, Transit Gateway, Public IPv4)
2. `Amazon Virtual Private Cloud` service (some VPC charges appear here)

Combine results for a complete VPC cost picture.

### Metrics Guide
| Metric | When to Use |
|---|---|
| `UnblendedCost` | Default. Actual cost per account. Best for understanding real charges. |
| `BlendedCost` | Averaged across organization. Useful for consolidated billing fairness. |
| `AmortizedCost` | Spreads upfront RI/SP payments across the term. Use when RIs or Savings Plans are active. |
| `NetAmortizedCost` | Amortized minus discounts. Best for true net cost with all discounts applied. |
| `UsageQuantity` | Raw usage amount. Only meaningful when filtered to a single USAGE_TYPE. |

### Filter Expression Syntax
Combine filters with `And`, `Or`, `Not`:

```json
{
  "And": [
    {"Dimensions": {"Key": "SERVICE", "Values": ["EC2 - Other"]}},
    {"Not": {"Dimensions": {"Key": "USAGE_TYPE", "Values": ["Tax"], "MatchOptions": ["CONTAINS"]}}}
  ]
}
```

MatchOptions: `EQUALS` (default), `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `ABSENT`.

### Common Analysis Patterns

1. **"Why is my bill high?"** — Start with Workflow 1 (top services), then Workflow 2 (drill into top spender by usage type), then Workflow 5 (daily trends to find spike date).

2. **"What's in EC2-Other?"** — Workflow 2 with `EC2 - Other` service filter. Map usage types to sub-categories using the table above.

3. **"Cost by team/environment"** — Workflow 3 (discover tags first, then group by the relevant tag). If no tags, suggest the user enable cost allocation tags.

4. **"Per-account breakdown"** — Workflow 4. Show top accounts, then offer to drill into a specific account's services.

5. **"Compare this month vs last month"** — Two Workflow 1 calls with different date ranges, then calculate deltas.

6. **"Data transfer costs"** — Workflow 2 with `EC2 - Other` filtered to `DataTransfer` usage types. Also check `Amazon CloudFront` for CDN transfer.

## Output Formatting

- Present costs as **markdown tables** sorted by amount descending
- Format currency: `$1,234.56` (2 decimal places, comma separators)
- Show **% of total** for each line item
- Round percentages to 1 decimal place
- For items < 1% of total, group as "Other (N services)" at the bottom
- For trends, show change with indicators: `+$150.23 (+12.5%)` or `-$50.00 (-3.2%)`
- For daily trends with many days, summarize the pattern and highlight anomalies rather than listing every day
- When showing account IDs, include the account name if available: `123456789012 (prod-account)`

## Fallback: boto3

When `aws ce` CLI is not available but Python and boto3 are installed, use inline Python:

```bash
python3 -c "
import boto3, json
ce = boto3.client('ce')
resp = ce.get_cost_and_usage(
    TimePeriod={'Start': 'YYYY-MM-DD', 'End': 'YYYY-MM-DD'},
    Granularity='MONTHLY',
    Metrics=['UnblendedCost'],
    GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
)
for period in resp['ResultsByTime']:
    groups = sorted(period['Groups'], key=lambda g: float(g['Metrics']['UnblendedCost']['Amount']), reverse=True)
    for g in groups:
        cost = float(g['Metrics']['UnblendedCost']['Amount'])
        if cost > 0.01:
            print(f'{g[\"Keys\"][0]}: \${cost:,.2f}')
"
```

For paginated results:

```bash
python3 -c "
import boto3, json
ce = boto3.client('ce')
results = []
params = dict(
    TimePeriod={'Start': 'YYYY-MM-DD', 'End': 'YYYY-MM-DD'},
    Granularity='MONTHLY',
    Metrics=['UnblendedCost'],
    GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}],
    Filter={'Dimensions': {'Key': 'SERVICE', 'Values': ['EC2 - Other']}}
)
while True:
    resp = ce.get_cost_and_usage(**params)
    results.extend(resp['ResultsByTime'])
    if 'NextPageToken' in resp:
        params['NextPageToken'] = resp['NextPageToken']
    else:
        break
for period in results:
    groups = sorted(period['Groups'], key=lambda g: float(g['Metrics']['UnblendedCost']['Amount']), reverse=True)
    for g in groups:
        cost = float(g['Metrics']['UnblendedCost']['Amount'])
        if cost > 0.01:
            print(f'{g[\"Keys\"][0]}: \${cost:,.2f}')
"
```

For discovering tags:

```bash
python3 -c "
import boto3, json
ce = boto3.client('ce')
resp = ce.get_tags(TimePeriod={'Start': 'YYYY-MM-DD', 'End': 'YYYY-MM-DD'})
print(json.dumps(resp['Tags'], indent=2))
"
```
