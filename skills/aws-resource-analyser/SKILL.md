---
name: aws-resource-analyser
description: >
  Analyze AWS resources across accounts and regions. Detect unused/idle resources,
  check tagging compliance, audit security posture, identify right-sizing opportunities,
  and track resource lifecycle. Triggers on: AWS resource inventory, unused resources,
  idle instances, unattached volumes, tagging compliance, security audit, public S3 buckets,
  unencrypted resources, right-sizing, resource age, orphaned snapshots, waste detection.
---

# AWS Resource Analyser

Analyze AWS resources to find waste, security gaps, tagging issues, and optimization opportunities. Works across accounts and regions.

## Safety — READ ONLY

This skill is strictly read-only. NEVER create, modify, delete, stop, or terminate any AWS resources. Only use `describe-*`, `list-*`, `get-*` API calls and CloudWatch metric reads. If the user asks to take action (e.g., "delete that volume", "terminate that instance"), explain the finding and recommend the action but do NOT execute it. The user must take remediation actions themselves.

## When to Activate

- User asks about AWS resource inventory or what's running
- Questions about unused, idle, or orphaned resources
- Tagging compliance or tag coverage analysis
- Security audit: public access, encryption, security groups, IAM hygiene
- Right-sizing or optimization questions
- Resource age or lifecycle analysis
- "What can I clean up?" or "Where am I wasting money?"

## Prerequisites

Verify AWS access:

```bash
aws sts get-caller-identity --output json
```

Check available regions (some commands need to run per-region):

```bash
aws ec2 describe-regions --query 'Regions[].RegionName' --output json
```

For multi-account analysis, check Organizations access:

```bash
aws organizations list-accounts --output json 2>/dev/null
```

**Important**: Many commands are region-specific. When doing a broad audit, iterate over relevant regions. Start with the user's default region, then expand if asked.

Get the current region:

```bash
aws configure get region
```

## Core Workflows

### 1. Resource Inventory

#### 1a. Quick Inventory via Resource Groups Tagging API

Lists all tagged resources across services in a single call:

```bash
aws resourcegroupstaggingapi get-resources \
  --output json \
  --query 'ResourceTagMappingList[].{ARN:ResourceARN}' | \
  python3 -c "
import json, sys, collections
resources = json.load(sys.stdin)
counts = collections.Counter()
for r in resources:
    service = r['ARN'].split(':')[2]
    counts[service] += 1
for svc, count in counts.most_common():
    print(f'{svc}: {count}')
"
```

Note: This only returns resources that have at least one tag. For a complete inventory, use service-specific commands below.

#### 1b. Service-Specific Counts

**EC2 Instances:**
```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' \
  --output table
```

**RDS Instances:**
```bash
aws rds describe-db-instances \
  --query 'DBInstances[].{Id:DBInstanceIdentifier,Class:DBInstanceClass,Engine:Engine,Status:DBInstanceStatus,MultiAZ:MultiAZ,Storage:AllocatedStorage}' \
  --output table
```

**Lambda Functions:**
```bash
aws lambda list-functions \
  --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Memory:MemorySize,Timeout:Timeout,LastModified:LastModified}' \
  --output table
```

**S3 Buckets:**
```bash
aws s3api list-buckets --query 'Buckets[].{Name:Name,Created:CreationDate}' --output table
```

**ECS Services:**
```bash
aws ecs list-clusters --query 'clusterArns[]' --output text | while read cluster; do
  echo "=== $cluster ==="
  aws ecs list-services --cluster "$cluster" --query 'serviceArns[]' --output text
done
```

**Load Balancers:**
```bash
aws elbv2 describe-load-balancers \
  --query 'LoadBalancers[].{Name:LoadBalancerName,Type:Type,Scheme:Scheme,State:State.Code,DNS:DNSName}' \
  --output table
```

**EBS Volumes:**
```bash
aws ec2 describe-volumes \
  --query 'Volumes[].{Id:VolumeId,Size:Size,Type:VolumeType,State:State,AZ:AvailabilityZone,Encrypted:Encrypted}' \
  --output table
```

#### 1c. Multi-Region Inventory

To scan all enabled regions for a specific resource type:

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  count=$(aws ec2 describe-instances --region "$region" --query 'length(Reservations[].Instances[])' --output text 2>/dev/null)
  if [ "$count" != "0" ] && [ "$count" != "None" ]; then
    echo "$region: $count instances"
  fi
done
```

### 2. Unused / Idle Resource Detection

#### 2a. Unattached EBS Volumes

```bash
aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --query 'Volumes[].{Id:VolumeId,Size:Size,Type:VolumeType,AZ:AvailabilityZone,Created:CreateTime}' \
  --output table
```

Cost impact: Each unattached volume is wasted storage cost. Calculate with size * price per GB-month (gp3: $0.08/GB, gp2: $0.10/GB, io1: $0.125/GB).

#### 2b. Idle EC2 Instances (Low CPU)

```bash
python3 -c "
import boto3, datetime

cw = boto3.client('cloudwatch')
ec2 = boto3.client('ec2')

instances = ec2.describe_instances(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
)

end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=7)

print(f'{'Instance ID':<22} {'Name':<30} {'Type':<15} {'Avg CPU %':<10}')
print('-' * 77)

for res in instances['Reservations']:
    for inst in res['Instances']:
        iid = inst['InstanceId']
        itype = inst['InstanceType']
        name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), '-')

        metrics = cw.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': iid}],
            StartTime=start, EndTime=end,
            Period=86400 * 7,
            Statistics=['Average']
        )

        avg_cpu = metrics['Datapoints'][0]['Average'] if metrics['Datapoints'] else -1
        if 0 <= avg_cpu < 5:
            print(f'{iid:<22} {name:<30} {itype:<15} {avg_cpu:<10.1f}')
"
```

Instances with <5% average CPU over 7 days are likely idle. Suggest stopping, rightsizing, or terminating.

#### 2c. Unassociated Elastic IPs

```bash
aws ec2 describe-addresses \
  --query 'Addresses[?AssociationId==null].{IP:PublicIp,AllocationId:AllocationId}' \
  --output table
```

Cost: $0.005/hour ($3.60/month) per idle EIP.

#### 2d. Old EBS Snapshots

```bash
python3 -c "
import boto3, datetime

ec2 = boto3.client('ec2')
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)

paginator = ec2.get_paginator('describe_snapshots')
old = []
for page in paginator.paginate(OwnerIds=['self']):
    for snap in page['Snapshots']:
        if snap['StartTime'] < cutoff:
            age_days = (datetime.datetime.now(datetime.timezone.utc) - snap['StartTime']).days
            old.append((snap['SnapshotId'], snap['VolumeSize'], age_days, snap.get('Description', '')[:50]))

old.sort(key=lambda x: x[2], reverse=True)
total_gb = sum(s[1] for s in old)
print(f'Found {len(old)} snapshots older than 90 days ({total_gb} GB total)')
print(f'Estimated cost: \${total_gb * 0.05:,.2f}/month')
print()
for sid, size, age, desc in old[:20]:
    print(f'{sid}  {size:>5} GB  {age:>4} days  {desc}')
if len(old) > 20:
    print(f'... and {len(old) - 20} more')
"
```

#### 2e. Orphaned AMIs

AMIs whose source instance no longer exists:

```bash
python3 -c "
import boto3

ec2 = boto3.client('ec2')
images = ec2.describe_images(Owners=['self'])['Images']
instances = set()
for res in ec2.describe_instances()['Reservations']:
    for inst in res['Instances']:
        instances.add(inst['InstanceId'])

for img in images:
    source = img.get('Name', '') + img.get('Description', '')
    # Check if any referenced instance still exists
    print(f'{img[\"ImageId\"]}  {img[\"CreationDate\"][:10]}  {img.get(\"Name\", \"-\")[:50]}')
print(f'Total: {len(images)} self-owned AMIs')
"
```

#### 2f. Load Balancers with No Healthy Targets

```bash
python3 -c "
import boto3

elbv2 = boto3.client('elbv2')
lbs = elbv2.describe_load_balancers()['LoadBalancers']

for lb in lbs:
    tgs = elbv2.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])['TargetGroups']
    all_unhealthy = True
    for tg in tgs:
        health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
        healthy = [t for t in health['TargetHealthDescriptions'] if t['TargetHealth']['State'] == 'healthy']
        if healthy:
            all_unhealthy = False
            break
    if all_unhealthy and tgs:
        print(f'{lb[\"LoadBalancerName\"]}  ({lb[\"Type\"]})  — NO healthy targets')
"
```

#### 2g. Unused NAT Gateways

```bash
python3 -c "
import boto3, datetime

ec2 = boto3.client('ec2')
cw = boto3.client('cloudwatch')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=7)

nats = ec2.describe_nat_gateways(Filter=[{'Name': 'state', 'Values': ['available']}])['NatGateways']

for nat in nats:
    nid = nat['NatGatewayId']
    metrics = cw.get_metric_statistics(
        Namespace='AWS/NATGateway',
        MetricName='BytesOutToDestination',
        Dimensions=[{'Name': 'NatGatewayId', 'Value': nid}],
        StartTime=start, EndTime=end,
        Period=86400 * 7,
        Statistics=['Sum']
    )
    total_bytes = metrics['Datapoints'][0]['Sum'] if metrics['Datapoints'] else 0
    if total_bytes == 0:
        subnet = nat.get('SubnetId', '-')
        print(f'{nid}  subnet={subnet}  — ZERO traffic in 7 days (\$0.045/hr wasted)')
"
```

#### 2h. Lambda Functions Not Invoked Recently

```bash
python3 -c "
import boto3, datetime

lam = boto3.client('lambda')
cw = boto3.client('cloudwatch')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=30)

functions = lam.list_functions()['Functions']
stale = []
for fn in functions:
    metrics = cw.get_metric_statistics(
        Namespace='AWS/Lambda',
        MetricName='Invocations',
        Dimensions=[{'Name': 'FunctionName', 'Value': fn['FunctionName']}],
        StartTime=start, EndTime=end,
        Period=86400 * 30,
        Statistics=['Sum']
    )
    invocations = metrics['Datapoints'][0]['Sum'] if metrics['Datapoints'] else 0
    if invocations == 0:
        stale.append(fn['FunctionName'])

print(f'{len(stale)} functions with zero invocations in 30 days:')
for name in sorted(stale):
    print(f'  {name}')
"
```

### 3. Tagging Compliance

#### 3a. Find Resources Missing Required Tags

```bash
python3 -c "
import boto3, json

required_tags = ['Environment', 'Team', 'CostCenter']  # Adjust to your org's requirements

client = boto3.client('resourcegroupstaggingapi')
paginator = client.get_paginator('get_resources')

missing = {tag: [] for tag in required_tags}
total = 0

for page in paginator.paginate():
    for resource in page['ResourceTagMappingList']:
        total += 1
        tags = {t['Key'] for t in resource['Tags']}
        for req in required_tags:
            if req not in tags:
                service = resource['ResourceARN'].split(':')[2]
                missing[req].append(f'{service}: {resource[\"ResourceARN\"].split(\":\")[-1][:60]}')

print(f'Scanned {total} tagged resources')
print()
for tag, resources in missing.items():
    pct = (1 - len(resources) / total) * 100 if total > 0 else 0
    print(f'{tag}: {pct:.1f}% coverage ({total - len(resources)}/{total})')
    for r in resources[:5]:
        print(f'  missing: {r}')
    if len(resources) > 5:
        print(f'  ... and {len(resources) - 5} more')
    print()
"
```

Adjust `required_tags` based on what the user's organization requires.

#### 3b. Tag Coverage by Service

```bash
python3 -c "
import boto3, collections

client = boto3.client('resourcegroupstaggingapi')
paginator = client.get_paginator('get_resources')

service_counts = collections.Counter()
service_tagged = collections.Counter()

for page in paginator.paginate():
    for resource in page['ResourceTagMappingList']:
        service = resource['ResourceARN'].split(':')[2]
        service_counts[service] += 1
        if len(resource['Tags']) > 0:
            service_tagged[service] += 1

print(f'{'Service':<30} {'Tagged':<10} {'Total':<10} {'Coverage':<10}')
print('-' * 60)
for service, total in service_counts.most_common():
    tagged = service_tagged[service]
    pct = (tagged / total) * 100
    print(f'{service:<30} {tagged:<10} {total:<10} {pct:<10.1f}%')
"
```

### 4. Security Posture

#### 4a. Public S3 Buckets

```bash
python3 -c "
import boto3, json

s3 = boto3.client('s3')
s3control = boto3.client('s3control')
sts = boto3.client('sts')
account_id = sts.get_caller_identity()['Account']

# Check account-level public access block
try:
    acct_block = s3control.get_public_access_block(AccountId=account_id)['PublicAccessBlockConfiguration']
    print('Account-level public access block:')
    for k, v in acct_block.items():
        status = 'BLOCKED' if v else 'OPEN'
        print(f'  {k}: {status}')
    print()
except:
    print('Account-level public access block: NOT SET')
    print()

buckets = s3.list_buckets()['Buckets']
for bucket in buckets:
    name = bucket['Name']
    try:
        pab = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
        all_blocked = all(pab.values())
    except:
        all_blocked = False

    if not all_blocked:
        print(f'{name} — public access block INCOMPLETE')
"
```

#### 4b. Unencrypted EBS Volumes

```bash
aws ec2 describe-volumes \
  --filters Name=encrypted,Values=false \
  --query 'Volumes[].{Id:VolumeId,Size:Size,Type:VolumeType,State:State,AttachedTo:Attachments[0].InstanceId}' \
  --output table
```

#### 4c. Publicly Accessible RDS Instances

```bash
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].{Id:DBInstanceIdentifier,Engine:Engine,Class:DBInstanceClass,Encrypted:StorageEncrypted}' \
  --output table
```

#### 4d. Wide-Open Security Groups

```bash
python3 -c "
import boto3

ec2 = boto3.client('ec2')
sgs = ec2.describe_security_groups()['SecurityGroups']

risky_ports = [22, 3389, 3306, 5432, 27017, 6379, 9200, 11211]

for sg in sgs:
    for rule in sg['IpPermissions']:
        for ip_range in rule.get('IpRanges', []):
            if ip_range['CidrIp'] == '0.0.0.0/0':
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                if from_port == 0 and to_port == 65535:
                    print(f'{sg[\"GroupId\"]} ({sg[\"GroupName\"]}) — ALL PORTS open to 0.0.0.0/0')
                elif any(from_port <= p <= to_port for p in risky_ports):
                    print(f'{sg[\"GroupId\"]} ({sg[\"GroupName\"]}) — port {from_port}-{to_port} open to 0.0.0.0/0')
"
```

#### 4e. IAM Hygiene

**Users without MFA:**
```bash
aws iam generate-credential-report > /dev/null 2>&1 && sleep 2
aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | python3 -c "
import csv, sys
reader = csv.DictReader(sys.stdin)
for row in reader:
    if row['mfa_active'] == 'false' and row['password_enabled'] == 'true':
        print(f'{row[\"user\"]}: password enabled, NO MFA')
"
```

**Old access keys (90+ days):**
```bash
python3 -c "
import boto3, datetime

iam = boto3.client('iam')
users = iam.list_users()['Users']
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)

for user in users:
    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
    for key in keys:
        if key['Status'] == 'Active' and key['CreateDate'] < cutoff:
            age = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
            print(f'{user[\"UserName\"]}: key {key[\"AccessKeyId\"]} is {age} days old')
"
```

### 5. Right-Sizing

#### 5a. EC2 Right-Sizing Recommendations (Cost Explorer)

```bash
aws ce get-rightsizing-recommendation \
  --service AmazonEC2 \
  --configuration '{"RecommendationTarget":"SAME_INSTANCE_FAMILY","BenefitsConsidered":true}' \
  --output json
```

Parse the response to show:
- Current instance type and cost
- Recommended instance type and projected cost
- Estimated monthly savings

#### 5b. EC2 CPU/Memory Analysis

```bash
python3 -c "
import boto3, datetime

ec2 = boto3.client('ec2')
cw = boto3.client('cloudwatch')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=14)

instances = []
for res in ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])['Reservations']:
    for inst in res['Instances']:
        instances.append(inst)

print(f'{'Instance':<22} {'Name':<25} {'Type':<15} {'Avg CPU':<10} {'Max CPU':<10}')
print('-' * 82)

for inst in instances:
    iid = inst['InstanceId']
    name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), '-')

    metrics = cw.get_metric_statistics(
        Namespace='AWS/EC2', MetricName='CPUUtilization',
        Dimensions=[{'Name': 'InstanceId', 'Value': iid}],
        StartTime=start, EndTime=end, Period=86400 * 14,
        Statistics=['Average', 'Maximum']
    )

    if metrics['Datapoints']:
        avg = metrics['Datapoints'][0]['Average']
        mx = metrics['Datapoints'][0]['Maximum']
        flag = ' << oversized' if mx < 30 else ''
        print(f'{iid:<22} {name:<25} {inst[\"InstanceType\"]:<15} {avg:<10.1f} {mx:<10.1f}{flag}')
"
```

Instances where max CPU < 30% over 14 days are likely oversized.

### 6. Resource Age / Lifecycle

#### 6a. EC2 Instance Age

```bash
python3 -c "
import boto3, datetime

ec2 = boto3.client('ec2')
now = datetime.datetime.now(datetime.timezone.utc)

instances = []
for res in ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])['Reservations']:
    for inst in res['Instances']:
        age = (now - inst['LaunchTime']).days
        name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), '-')
        instances.append((age, inst['InstanceId'], inst['InstanceType'], name))

instances.sort(reverse=True)
print(f'{'Age (days)':<12} {'Instance':<22} {'Type':<15} {'Name':<30}')
print('-' * 79)
for age, iid, itype, name in instances:
    flag = ' << very old' if age > 365 else ''
    print(f'{age:<12} {iid:<22} {itype:<15} {name:<30}{flag}')
"
```

#### 6b. Stale CloudFormation Stacks

```bash
python3 -c "
import boto3, datetime

cf = boto3.client('cloudformation')
now = datetime.datetime.now(datetime.timezone.utc)
cutoff = now - datetime.timedelta(days=180)

paginator = cf.get_paginator('list_stacks')
for page in paginator.paginate(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'ROLLBACK_COMPLETE']):
    for stack in page['StackSummaries']:
        last_updated = stack.get('LastUpdatedTime', stack['CreationTime'])
        if last_updated < cutoff:
            age = (now - last_updated).days
            print(f'{stack[\"StackName\"]}: last updated {age} days ago ({stack[\"StackStatus\"]})')
"
```

### 7. Cross-Account / Multi-Region View

#### 7a. Resource Count by Region

```bash
python3 -c "
import boto3

ec2_client = boto3.client('ec2')
regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]

print(f'{'Region':<20} {'EC2':<8} {'RDS':<8} {'Lambda':<8} {'EBS':<8}')
print('-' * 52)

for region in sorted(regions):
    try:
        ec2 = boto3.client('ec2', region_name=region)
        rds = boto3.client('rds', region_name=region)
        lam = boto3.client('lambda', region_name=region)

        ec2_count = sum(len(r['Instances']) for r in ec2.describe_instances()['Reservations'])
        rds_count = len(rds.describe_db_instances()['DBInstances'])
        lam_count = len(lam.list_functions()['Functions'])
        ebs_count = len(ec2.describe_volumes()['Volumes'])

        if ec2_count + rds_count + lam_count + ebs_count > 0:
            print(f'{region:<20} {ec2_count:<8} {rds_count:<8} {lam_count:<8} {ebs_count:<8}')
    except Exception as e:
        pass
"
```

Note: This can be slow across all regions. Suggest running only when the user explicitly asks for a full multi-region scan. For quick checks, use the user's default region.

#### 7b. Multi-Account Resource Summary (Organizations)

```bash
python3 -c "
import boto3

org = boto3.client('organizations')
accounts = org.list_accounts()['Accounts']

print(f'{'Account ID':<15} {'Name':<30} {'Status':<10} {'Email':<35}')
print('-' * 90)
for acct in accounts:
    print(f'{acct[\"Id\"]:<15} {acct[\"Name\"]:<30} {acct[\"Status\"]:<10} {acct[\"Email\"]:<35}')

print(f'\nTotal: {len(accounts)} accounts')
print('Note: To get resource counts per account, assume a role in each account.')
"
```

For per-account resource analysis, the agent should assume a role in the target account:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/OrganizationAccountAccessRole \
  --role-session-name resource-audit \
  --output json
```

Then use the temporary credentials for subsequent commands.

## Domain Knowledge

### Waste Detection Priority

Order of typical waste impact (highest savings first):

1. **Idle EC2 instances** — Often the biggest waste. A single unused m5.xlarge costs ~$140/month.
2. **Unattached EBS volumes** — Forgotten after instance termination. Accumulates silently.
3. **Old snapshots** — Grow unbounded. Organizations often have TBs of stale snapshots.
4. **Unused NAT Gateways** — $32/month each even with zero traffic.
5. **Idle Elastic IPs** — Small ($3.60/month) but adds up.
6. **Oversized instances** — Right-sizing can save 30-50% on compute.
7. **Unused load balancers** — $16-22/month per ALB/NLB with no traffic.

### Common Service-Specific Gotchas

- **EBS**: Volumes persist after EC2 termination if `DeleteOnTermination` is false (the default for additional volumes).
- **Snapshots**: AMI deregistration doesn't delete associated snapshots. They become orphaned.
- **Elastic IPs**: Only free when attached to a running instance. Stopped instance = charged.
- **NAT Gateways**: Charged per hour AND per GB processed. Two cost dimensions.
- **Lambda**: No cost when idle, but stale functions clutter the environment and may have security implications.
- **Security Groups**: Can't delete SGs that are referenced by other SGs or attached to ENIs. Check dependencies first.

### Cross-Reference with Cost Analyser

When you find unused resources, help the user understand the cost impact by suggesting they use the `aws-cost-analyser` skill:

- Found idle EC2? → "Use the cost analyser to see how much these instances cost last month"
- Found old snapshots? → "Check EBS snapshot costs in EC2-Other breakdown"
- Found unused NAT? → "Look at NAT Gateway costs in the EC2-Other usage type drill-down"

### Rate Limiting

Some AWS APIs have low rate limits. When scanning many resources:
- CloudWatch `GetMetricStatistics`: 400 transactions/second
- EC2 `DescribeInstances`: 100 requests/second
- For large inventories, add brief pauses or batch requests
- Prefer `describe-*` with filters over listing everything and filtering client-side

### Permissions Required

The following IAM permissions are needed for a comprehensive audit:
- `ec2:Describe*` — instances, volumes, snapshots, security groups, addresses, NAT gateways
- `rds:Describe*` — DB instances
- `lambda:ListFunctions` — Lambda inventory
- `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock` — S3 audit
- `elasticloadbalancing:Describe*` — load balancers and target groups
- `cloudwatch:GetMetricStatistics` — utilization metrics
- `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListUsers`, `iam:ListAccessKeys` — IAM audit
- `ce:GetRightsizingRecommendation` — right-sizing
- `organizations:ListAccounts` — multi-account
- `tag:GetResources` — tagging inventory
- `cloudformation:ListStacks` — stack lifecycle

The `ReadOnlyAccess` managed policy covers most of these.

## Output Formatting

- Present findings as **markdown tables** sorted by impact (cost or risk)
- Show estimated **monthly cost** for each wasted resource
- Use severity indicators: `CRITICAL` (security), `HIGH` (>$50/month waste), `MEDIUM` ($10-50), `LOW` (<$10)
- Group findings by category (waste, security, tagging, sizing)
- Always include **actionable recommendations** (terminate, resize, encrypt, etc.)
- For multi-region results, prefix with region name
- Show totals and summary at the end: "Found X issues, estimated $Y/month in waste"
