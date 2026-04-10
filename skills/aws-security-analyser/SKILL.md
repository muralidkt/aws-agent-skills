---
name: aws-security-analyser
description: >
  Analyze AWS security posture using native security services. Triggers on: GuardDuty
  findings, Security Hub scores, CloudTrail audit, AWS Config compliance, VPC Flow Logs,
  WAF rules, KMS key policies, Secrets Manager rotation, certificate expiry, Macie
  findings, security posture, compliance check, threat detection, security dashboard.
---

# AWS Security Analyser

Analyze AWS security posture by aggregating findings from native security services: GuardDuty, Security Hub, CloudTrail, AWS Config, VPC Flow Logs, WAF, KMS, Secrets Manager, Certificate Manager, and Macie.

## Safety — READ ONLY

This skill is strictly read-only. NEVER create, modify, or delete any AWS resources or security configurations. Only use `list-*`, `get-*`, `describe-*` API calls. If the user asks to take action (e.g., "enable GuardDuty", "fix that finding"), explain the finding and recommend the action but do NOT execute it. The user must take remediation actions themselves.

## When to Activate

- User asks about overall security posture or compliance status
- Questions about GuardDuty threats or Security Hub findings
- CloudTrail audit: is logging enabled, are there gaps?
- AWS Config compliance checks
- VPC Flow Logs status or rejected traffic analysis
- WAF configuration review
- KMS key policy or rotation audit
- Secrets Manager rotation status
- SSL/TLS certificate expiry checks
- Macie sensitive data findings
- "Is my account secure?" or "What security issues do I have?"

## Prerequisites

Verify AWS access:

```bash
aws sts get-caller-identity --output json
```

Get the current region:

```bash
aws configure get region
```

Many security services are regional. Start with the current region, expand if asked.

Check Organizations access (needed for multi-account security posture):

```bash
aws organizations describe-organization --output json 2>/dev/null
```

## Core Workflows

### 1. GuardDuty — Threat Detection

#### 1a. Check GuardDuty Status

```bash
python3 -c "
import boto3

gd = boto3.client('guardduty')

detectors = gd.list_detectors()['DetectorIds']
if not detectors:
    print('GuardDuty: NOT ENABLED')
    print('CRITICAL: No threat detection active. GuardDuty should be enabled in all accounts/regions.')
else:
    for did in detectors:
        detail = gd.get_detector(DetectorId=did)
        print(f'GuardDuty Detector: {did}')
        print(f'  Status: {detail[\"Status\"]}')
        print(f'  Created: {detail.get(\"CreatedAt\", \"-\")}')
        print(f'  Updated: {detail.get(\"UpdatedAt\", \"-\")}')

        # Check enabled features
        features = detail.get('Features', [])
        if features:
            print(f'  Features:')
            for f in features:
                print(f'    {f[\"Name\"]}: {f[\"Status\"]}')

        # Check data sources (legacy)
        ds = detail.get('DataSources', {})
        if ds:
            for source, config in ds.items():
                status = config.get('Status', 'unknown')
                print(f'  {source}: {status}')
"
```

#### 1b. Active Findings Summary

```bash
python3 -c "
import boto3, json
from collections import Counter

gd = boto3.client('guardduty')
detectors = gd.list_detectors()['DetectorIds']

if not detectors:
    print('GuardDuty not enabled.')
    exit()

detector_id = detectors[0]

# Get active findings
criteria = {'criterion': {'service.archived': {'Eq': ['false']}}}
finding_ids = []

paginator_params = {
    'DetectorId': detector_id,
    'FindingCriteria': criteria,
    'SortCriteria': {'AttributeName': 'severity', 'OrderBy': 'DESC'}
}

# List findings (paginate manually)
response = gd.list_findings(**paginator_params, MaxResults=50)
finding_ids.extend(response['FindingIds'])

if not finding_ids:
    print('No active GuardDuty findings. Good.')
    exit()

findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50])['Findings']

# Summarize by severity
severity_map = {8: 'HIGH', 5: 'MEDIUM', 2: 'LOW'}
by_severity = Counter()
by_type = Counter()

for f in findings:
    sev = f['Severity']
    if sev >= 7:
        by_severity['HIGH'] += 1
    elif sev >= 4:
        by_severity['MEDIUM'] += 1
    else:
        by_severity['LOW'] += 1
    by_type[f['Type']] += 1

print(f'Active GuardDuty Findings: {len(finding_ids)}\n')

print('By severity:')
for sev in ['HIGH', 'MEDIUM', 'LOW']:
    if by_severity[sev]:
        print(f'  {sev}: {by_severity[sev]}')

print(f'\nBy type:')
for ftype, count in by_type.most_common(10):
    print(f'  {ftype}: {count}')

print(f'\nTop findings:')
for f in findings[:5]:
    sev = 'HIGH' if f['Severity'] >= 7 else 'MEDIUM' if f['Severity'] >= 4 else 'LOW'
    print(f'  [{sev}] {f[\"Type\"]}')
    print(f'    {f[\"Title\"]}')
    resource = f.get('Resource', {})
    resource_type = resource.get('ResourceType', '-')
    print(f'    Resource: {resource_type}')
    print()
"
```

### 2. Security Hub — Compliance & Findings

#### 2a. Check Security Hub Status and Standards

```bash
python3 -c "
import boto3

sh = boto3.client('securityhub')

try:
    hub = sh.describe_hub()
    print(f'Security Hub: ENABLED')
    print(f'  Hub ARN: {hub[\"HubArn\"]}')
    print(f'  Subscribed: {hub.get(\"SubscribedAt\", \"-\")}')
    print(f'  Auto-enable controls: {hub.get(\"AutoEnableControls\", \"-\")}')
    print()

    # List enabled standards
    standards = sh.get_enabled_standards()['StandardsSubscriptions']
    print(f'Enabled Standards ({len(standards)}):')
    for std in standards:
        name = std['StandardsArn'].split('/')[-1]
        print(f'  {name}: {std[\"StandardsStatus\"]}')

except sh.exceptions.InvalidAccessException:
    print('Security Hub: NOT ENABLED')
    print('CRITICAL: No centralized security findings aggregation.')
    print('Recommendation: Enable Security Hub with CIS AWS Foundations Benchmark.')
except Exception as e:
    print(f'Error: {e}')
"
```

#### 2b. Compliance Score by Standard

```bash
python3 -c "
import boto3

sh = boto3.client('securityhub')

try:
    standards = sh.get_enabled_standards()['StandardsSubscriptions']

    for std in standards:
        std_arn = std['StandardsSubscriptionArn']
        name = std['StandardsArn'].split('/')[-1]

        # Get controls for this standard
        controls = []
        next_token = None
        while True:
            params = {'StandardsSubscriptionArn': std_arn, 'MaxResults': 100}
            if next_token:
                params['NextToken'] = next_token
            resp = sh.describe_standards_controls(**params)
            controls.extend(resp['Controls'])
            next_token = resp.get('NextToken')
            if not next_token:
                break

        total = len(controls)
        passed = sum(1 for c in controls if c.get('ComplianceStatus') == 'PASSED')
        failed = sum(1 for c in controls if c.get('ComplianceStatus') == 'FAILED')
        unknown = total - passed - failed

        score = (passed / total * 100) if total > 0 else 0

        print(f'{name}:')
        print(f'  Score: {score:.1f}%')
        print(f'  Passed: {passed}, Failed: {failed}, Unknown: {unknown} (Total: {total})')

        # Show top failed controls
        failed_controls = [c for c in controls if c.get('ComplianceStatus') == 'FAILED']
        if failed_controls:
            failed_controls.sort(key=lambda c: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(c.get('SeverityRating', 'LOW'), 4))
            print(f'  Top failed controls:')
            for c in failed_controls[:5]:
                print(f'    [{c.get(\"SeverityRating\", \"-\")}] {c[\"ControlId\"]}: {c[\"Title\"]}')
        print()

except Exception as e:
    print(f'Error: {e}')
"
```

#### 2c. Critical and High Findings

```bash
python3 -c "
import boto3
from collections import Counter

sh = boto3.client('securityhub')

try:
    findings = []
    next_token = None

    filters = {
        'SeverityLabel': [{'Value': 'CRITICAL', 'Comparison': 'EQUALS'}, {'Value': 'HIGH', 'Comparison': 'EQUALS'}],
        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}, {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}],
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
    }

    resp = sh.get_findings(Filters=filters, MaxResults=100)
    findings = resp['Findings']

    by_severity = Counter()
    by_product = Counter()
    by_type = Counter()

    for f in findings:
        by_severity[f['Severity']['Label']] += 1
        by_product[f.get('ProductName', f['ProductArn'].split('/')[-1])] += 1
        for t in f.get('Types', []):
            by_type[t.split('/')[-1]] += 1

    print(f'Active Critical/High Findings: {len(findings)}\n')

    print('By severity:')
    for sev in ['CRITICAL', 'HIGH']:
        if by_severity[sev]:
            print(f'  {sev}: {by_severity[sev]}')

    print(f'\nBy source:')
    for product, count in by_product.most_common(10):
        print(f'  {product}: {count}')

    print(f'\nBy type:')
    for ftype, count in by_type.most_common(10):
        print(f'  {ftype}: {count}')

    if findings:
        print(f'\nTop findings:')
        for f in findings[:5]:
            print(f'  [{f[\"Severity\"][\"Label\"]}] {f[\"Title\"][:80]}')
            print(f'    Resource: {f[\"Resources\"][0][\"Type\"] if f.get(\"Resources\") else \"-\"}')
            print()

except Exception as e:
    print(f'Error: {e}')
"
```

### 3. CloudTrail — Audit Logging

#### 3a. CloudTrail Status

```bash
python3 -c "
import boto3

ct = boto3.client('cloudtrail')

trails = ct.describe_trails()['trailList']

if not trails:
    print('CloudTrail: NO TRAILS CONFIGURED')
    print('CRITICAL: No API activity logging. All AWS API calls are unaudited.')
    exit()

print(f'Found {len(trails)} CloudTrail trails:\n')

for trail in trails:
    name = trail['Name']
    status = ct.get_trail_status(Name=trail['TrailARN'])

    print(f'{name}:')
    print(f'  Multi-region: {trail.get(\"IsMultiRegionTrail\", False)}')
    print(f'  Organization trail: {trail.get(\"IsOrganizationTrail\", False)}')
    print(f'  Logging: {status.get(\"IsLogging\", False)}')
    print(f'  S3 bucket: {trail.get(\"S3BucketName\", \"-\")}')
    print(f'  Log file validation: {trail.get(\"LogFileValidationEnabled\", False)}')
    print(f'  KMS encrypted: {\"Yes\" if trail.get(\"KmsKeyId\") else \"No\"}')

    if trail.get('CloudWatchLogsLogGroupArn'):
        print(f'  CloudWatch Logs: enabled')
    else:
        print(f'  CloudWatch Logs: NOT configured — no real-time alerting')

    latest = status.get('LatestDeliveryTime')
    if latest:
        import datetime
        age_hours = (datetime.datetime.now(datetime.timezone.utc) - latest).total_seconds() / 3600
        lag = f'{age_hours:.1f} hours ago'
        flag = ' << STALE' if age_hours > 24 else ''
        print(f'  Last delivery: {lag}{flag}')

    errors = status.get('LatestDeliveryError')
    if errors:
        print(f'  DELIVERY ERROR: {errors}')

    print()

# Check for management events coverage
has_multi_region = any(t.get('IsMultiRegionTrail') for t in trails)
has_logging = any(ct.get_trail_status(Name=t['TrailARN']).get('IsLogging') for t in trails)

if not has_multi_region:
    print('WARNING: No multi-region trail — API calls in other regions are not logged')
if not has_logging:
    print('CRITICAL: No trail is actively logging')
"
```

#### 3b. CloudTrail Event Selectors

```bash
python3 -c "
import boto3, json

ct = boto3.client('cloudtrail')
trails = ct.describe_trails()['trailList']

for trail in trails:
    name = trail['Name']
    print(f'=== {name} ===')

    # Check event selectors
    try:
        selectors = ct.get_event_selectors(TrailName=trail['TrailARN'])

        # Basic event selectors
        for es in selectors.get('EventSelectors', []):
            print(f'  Read/Write: {es.get(\"ReadWriteType\", \"-\")}')
            print(f'  Management events: {es.get(\"IncludeManagementEvents\", \"-\")}')
            data_resources = es.get('DataResources', [])
            if data_resources:
                print(f'  Data events:')
                for dr in data_resources:
                    print(f'    {dr[\"Type\"]}: {dr.get(\"Values\", [\"all\"])}')
            else:
                print(f'  Data events: NOT configured (S3, Lambda data events not logged)')

        # Advanced event selectors
        for aes in selectors.get('AdvancedEventSelectors', []):
            print(f'  Advanced selector: {aes.get(\"Name\", \"-\")}')
            for fs in aes.get('FieldSelectors', []):
                print(f'    {fs[\"Field\"]}: {fs.get(\"Equals\", fs.get(\"StartsWith\", \"-\"))}')

    except Exception as e:
        print(f'  Error reading selectors: {e}')

    print()
"
```

### 4. AWS Config — Compliance Rules

#### 4a. Config Recorder Status

```bash
python3 -c "
import boto3

config = boto3.client('config')

recorders = config.describe_configuration_recorders().get('ConfigurationRecorders', [])
statuses = config.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])

if not recorders:
    print('AWS Config: NOT ENABLED')
    print('CRITICAL: No configuration recording — cannot track resource compliance or changes.')
    exit()

for rec, status in zip(recorders, statuses):
    print(f'Config Recorder: {rec[\"name\"]}')
    print(f'  Recording: {status.get(\"recording\", False)}')
    print(f'  Last status: {status.get(\"lastStatus\", \"-\")}')
    print(f'  All resources: {rec.get(\"recordingGroup\", {}).get(\"allSupported\", False)}')
    print(f'  Include global: {rec.get(\"recordingGroup\", {}).get(\"includeGlobalResourceTypes\", False)}')

    if not status.get('recording'):
        print(f'  WARNING: Recorder is NOT actively recording')

# Delivery channel
channels = config.describe_delivery_channels().get('DeliveryChannels', [])
for ch in channels:
    print(f'\nDelivery Channel:')
    print(f'  S3 bucket: {ch.get(\"s3BucketName\", \"-\")}')
    print(f'  SNS topic: {ch.get(\"snsTopicARN\", \"not configured\")}')
"
```

#### 4b. Config Rule Compliance Summary

```bash
python3 -c "
import boto3

config = boto3.client('config')

try:
    summary = config.get_compliance_summary_by_config_rule()['ComplianceSummary']

    compliant = summary.get('CompliantResourceCount', {}).get('CappedCount', 0)
    non_compliant = summary.get('NonCompliantResourceCount', {}).get('CappedCount', 0)
    total = compliant + non_compliant
    score = (compliant / total * 100) if total > 0 else 0

    print(f'Config Rule Compliance: {score:.1f}%')
    print(f'  Compliant: {compliant}')
    print(f'  Non-compliant: {non_compliant}')
    print()

    # Get non-compliant rules
    paginator = config.get_paginator('describe_compliance_by_config_rule')
    non_compliant_rules = []

    for page in paginator.paginate(ComplianceTypes=['NON_COMPLIANT']):
        for rule in page['ComplianceByConfigRules']:
            non_compliant_rules.append(rule)

    if non_compliant_rules:
        print(f'Non-compliant rules ({len(non_compliant_rules)}):')
        for rule in non_compliant_rules[:15]:
            name = rule['ConfigRuleName']
            count = rule['Compliance'].get('ComplianceContributorCount', {}).get('CappedCount', '?')
            print(f'  {name}: {count} non-compliant resources')

        if len(non_compliant_rules) > 15:
            print(f'  ... and {len(non_compliant_rules) - 15} more')
    else:
        print('All Config rules are compliant.')

except Exception as e:
    print(f'Error: {e}')
"
```

#### 4c. Non-Compliant Resources for a Specific Rule

```bash
python3 -c "
import boto3

config = boto3.client('config')

# Get all non-compliant rules first
paginator = config.get_paginator('describe_compliance_by_config_rule')
rules = []
for page in paginator.paginate(ComplianceTypes=['NON_COMPLIANT']):
    rules.extend(page['ComplianceByConfigRules'])

for rule in rules[:5]:
    rule_name = rule['ConfigRuleName']
    print(f'=== {rule_name} ===')

    results = config.get_compliance_details_by_config_rule(
        ConfigRuleName=rule_name,
        ComplianceTypes=['NON_COMPLIANT'],
        Limit=10
    )

    for result in results['EvaluationResults']:
        resource = result['EvaluationResultIdentifier']['EvaluationResultQualifier']
        print(f'  {resource[\"ResourceType\"]}: {resource[\"ResourceId\"]}')

    print()
"
```

### 5. VPC Flow Logs

#### 5a. Check Flow Log Coverage

```bash
python3 -c "
import boto3

ec2 = boto3.client('ec2')

vpcs = ec2.describe_vpcs()['Vpcs']
flow_logs = ec2.describe_flow_logs()['FlowLogs']

# Map flow logs to VPCs
covered_vpcs = set()
for fl in flow_logs:
    if fl['ResourceId'].startswith('vpc-'):
        covered_vpcs.add(fl['ResourceId'])

print(f'VPC Flow Log Coverage:\n')
print(f'  Total VPCs: {len(vpcs)}')
print(f'  With flow logs: {len(covered_vpcs)}')
print(f'  Without flow logs: {len(vpcs) - len(covered_vpcs)}')
print()

for vpc in vpcs:
    vpc_id = vpc['VpcId']
    name = next((t['Value'] for t in vpc.get('Tags', []) if t['Key'] == 'Name'), '-')
    covered = vpc_id in covered_vpcs
    status = 'COVERED' if covered else 'NOT COVERED'
    print(f'  {vpc_id} ({name}): {status}')

uncovered = [v for v in vpcs if v['VpcId'] not in covered_vpcs]
if uncovered:
    print(f'\nWARNING: {len(uncovered)} VPCs have no flow logs — network traffic is unmonitored')

# Detail on active flow logs
if flow_logs:
    print(f'\nActive Flow Logs ({len(flow_logs)}):')
    for fl in flow_logs:
        dest = fl.get('LogDestination', fl.get('LogGroupName', '-'))
        print(f'  {fl[\"FlowLogId\"]}: {fl[\"ResourceId\"]} -> {fl[\"LogDestinationType\"]} ({fl[\"FlowLogStatus\"]})')
"
```

#### 5b. Flow Log Rejected Traffic Summary

```bash
python3 -c "
import boto3, datetime

cw_logs = boto3.client('logs')
ec2 = boto3.client('ec2')

flow_logs = ec2.describe_flow_logs()['FlowLogs']

# Find flow logs that go to CloudWatch
cw_flow_logs = [fl for fl in flow_logs if fl['LogDestinationType'] == 'cloud-watch-logs']

if not cw_flow_logs:
    print('No flow logs shipping to CloudWatch Logs.')
    print('Note: Flow logs to S3 require Athena queries for analysis.')
    exit()

for fl in cw_flow_logs:
    log_group = fl.get('LogGroupName')
    if not log_group:
        continue

    print(f'Flow Log: {fl[\"FlowLogId\"]} ({fl[\"ResourceId\"]})')
    print(f'  Log group: {log_group}')

    # Use CloudWatch Logs Insights for rejected traffic
    # Note: This requires the user to run a query — we show the query
    print(f'  To analyze rejected traffic, run:')
    print(f'    aws logs start-query \\\\')
    print(f'      --log-group-name {log_group} \\\\')
    print(f'      --start-time $(date -d \"7 days ago\" +%s) \\\\')
    print(f'      --end-time $(date +%s) \\\\')
    print(f'      --query-string \"fields @timestamp, srcAddr, dstAddr, dstPort, action | filter action=\\\"REJECT\\\" | stats count(*) by dstPort | sort count desc | limit 20\"')
    print()
"
```

### 6. WAF — Web Application Firewall

#### 6a. WAF Web ACLs

```bash
python3 -c "
import boto3

wafv2 = boto3.client('wafv2')

for scope in ['REGIONAL', 'CLOUDFRONT']:
    try:
        region_note = ' (us-east-1 only)' if scope == 'CLOUDFRONT' else ''
        acls = wafv2.list_web_acls(Scope=scope)['WebACLs']

        if acls:
            print(f'{scope} Web ACLs{region_note} ({len(acls)}):')
            for acl in acls:
                print(f'  {acl[\"Name\"]}')
                print(f'    ID: {acl[\"Id\"]}')

                # Get detail
                detail = wafv2.get_web_acl(Name=acl['Name'], Scope=scope, Id=acl['Id'])['WebACL']

                rules = detail.get('Rules', [])
                print(f'    Rules: {len(rules)}')
                for rule in rules[:5]:
                    action = rule.get('Action', rule.get('OverrideAction', {}))
                    action_type = list(action.keys())[0] if action else '-'
                    print(f'      {rule[\"Name\"]}: priority={rule[\"Priority\"]}, action={action_type}')
                if len(rules) > 5:
                    print(f'      ... and {len(rules) - 5} more')

                default_action = list(detail.get('DefaultAction', {}).keys())
                print(f'    Default action: {default_action[0] if default_action else \"-\"}')
            print()
    except Exception as e:
        if 'WAFNonexistentItemException' not in str(e):
            print(f'  {scope}: {e}')
"
```

#### 6b. WAF Associated Resources

```bash
python3 -c "
import boto3

wafv2 = boto3.client('wafv2')

acls = wafv2.list_web_acls(Scope='REGIONAL')['WebACLs']

for acl in acls:
    arn = acl['ARN']
    print(f'{acl[\"Name\"]}:')

    resources = wafv2.list_resources_for_web_acl(WebACLArn=arn)['ResourceArns']
    if resources:
        for r in resources:
            service = r.split(':')[2]
            resource_name = r.split('/')[-1]
            print(f'  {service}: {resource_name}')
    else:
        print(f'  No resources associated — WAF is not protecting anything')

    print()
"
```

### 7. KMS — Key Management

#### 7a. KMS Key Audit

```bash
python3 -c "
import boto3, datetime

kms = boto3.client('kms')

paginator = kms.get_paginator('list_keys')
keys = []
for page in paginator.paginate():
    keys.extend(page['Keys'])

print(f'Found {len(keys)} KMS keys:\n')

customer_keys = 0
for key in keys:
    key_id = key['KeyId']
    try:
        detail = kms.describe_key(KeyId=key_id)['KeyMetadata']

        # Skip AWS-managed keys for detailed audit
        if detail['KeyManager'] == 'AWS':
            continue

        customer_keys += 1
        state = detail['KeyState']
        rotation = 'unknown'

        try:
            rot = kms.get_key_rotation_status(KeyId=key_id)
            rotation = 'enabled' if rot['KeyRotationEnabled'] else 'DISABLED'
        except Exception:
            pass

        # Get aliases
        aliases = kms.list_aliases(KeyId=key_id)['Aliases']
        alias_names = [a['AliasName'] for a in aliases]

        print(f'{key_id}')
        print(f'  Aliases: {\", \".join(alias_names) if alias_names else \"none\"}')
        print(f'  State: {state}')
        print(f'  Rotation: {rotation}')
        print(f'  Created: {detail[\"CreationDate\"].strftime(\"%Y-%m-%d\")}')
        print(f'  Key spec: {detail.get(\"KeySpec\", \"-\")}')
        print(f'  Usage: {detail.get(\"KeyUsage\", \"-\")}')

        if rotation == 'DISABLED':
            print(f'  WARNING: Key rotation not enabled')
        if state == 'PendingDeletion':
            print(f'  NOTE: Key is pending deletion')

        print()

    except Exception:
        pass

print(f'Customer-managed keys audited: {customer_keys}')
"
```

#### 7b. KMS Key Policy Analysis

```bash
python3 -c "
import boto3, json

kms = boto3.client('kms')
sts = boto3.client('sts')
own_account = sts.get_caller_identity()['Account']

paginator = kms.get_paginator('list_keys')
risky = []

for page in paginator.paginate():
    for key in page['Keys']:
        key_id = key['KeyId']
        try:
            detail = kms.describe_key(KeyId=key_id)['KeyMetadata']
            if detail['KeyManager'] == 'AWS':
                continue

            policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName='default')['Policy'])

            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue

                principal = stmt.get('Principal', {})
                if isinstance(principal, str):
                    if principal == '*':
                        conditions = stmt.get('Condition', {})
                        risky.append({
                            'key': key_id,
                            'issue': 'Principal * (any AWS principal)',
                            'condition': 'yes' if conditions else 'NONE',
                            'severity': 'CRITICAL' if not conditions else 'HIGH'
                        })
                else:
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if p == '*':
                            risky.append({
                                'key': key_id,
                                'issue': 'AWS principal *',
                                'condition': 'yes' if stmt.get('Condition') else 'NONE',
                                'severity': 'CRITICAL' if not stmt.get('Condition') else 'HIGH'
                            })
                        elif ':root' in p:
                            acct = p.split(':')[4]
                            if acct != own_account:
                                risky.append({
                                    'key': key_id,
                                    'issue': f'Cross-account root: {acct}',
                                    'condition': 'yes' if stmt.get('Condition') else 'none',
                                    'severity': 'MEDIUM'
                                })
        except Exception:
            pass

if risky:
    risky.sort(key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['severity'], 3))
    print(f'Found {len(risky)} KMS key policy concerns:\n')
    for r in risky:
        print(f'  [{r[\"severity\"]}] {r[\"key\"]}')
        print(f'    {r[\"issue\"]} (conditions: {r[\"condition\"]})')
        print()
else:
    print('No risky KMS key policies found.')
"
```

### 8. Secrets Manager — Rotation Audit

```bash
python3 -c "
import boto3, datetime

sm = boto3.client('secretsmanager')
now = datetime.datetime.now(datetime.timezone.utc)

paginator = sm.get_paginator('list_secrets')
secrets = []
for page in paginator.paginate():
    secrets.extend(page['SecretList'])

if not secrets:
    print('No secrets found in Secrets Manager.')
    exit()

print(f'Found {len(secrets)} secrets:\n')

no_rotation = []
stale = []

for s in secrets:
    name = s['Name']
    rotation_enabled = s.get('RotationEnabled', False)
    last_rotated = s.get('LastRotatedDate')
    last_accessed = s.get('LastAccessedDate')
    last_changed = s.get('LastChangedDate')

    if not rotation_enabled:
        no_rotation.append(name)

    if last_changed:
        age_days = (now - last_changed).days
        if age_days > 90:
            stale.append((name, age_days))

if no_rotation:
    print(f'Secrets without rotation ({len(no_rotation)}):')
    for name in no_rotation:
        print(f'  {name}')
    print()

if stale:
    stale.sort(key=lambda x: x[1], reverse=True)
    print(f'Secrets not changed in 90+ days ({len(stale)}):')
    for name, age in stale:
        print(f'  {name}: {age} days old')
    print()

rotated_count = len(secrets) - len(no_rotation)
print(f'Summary: {rotated_count}/{len(secrets)} secrets have rotation enabled')
if no_rotation:
    print(f'Recommendation: Enable automatic rotation for {len(no_rotation)} secrets')
"
```

### 9. Certificate Manager — Expiry Check

```bash
python3 -c "
import boto3, datetime

acm = boto3.client('acm')
now = datetime.datetime.now(datetime.timezone.utc)

paginator = acm.get_paginator('list_certificates')
certs = []
for page in paginator.paginate():
    certs.extend(page['CertificateSummaryList'])

if not certs:
    print('No ACM certificates found.')
    exit()

expiring_soon = []
expired = []
ok = []

for cert in certs:
    arn = cert['CertificateArn']
    detail = acm.describe_certificate(CertificateArn=arn)['Certificate']

    domain = detail['DomainName']
    status = detail['Status']
    not_after = detail.get('NotAfter')
    cert_type = detail.get('Type', '-')
    in_use = len(detail.get('InUseBy', [])) > 0

    if not_after:
        days_left = (not_after - now).days
        if days_left < 0:
            expired.append((domain, days_left, status, in_use, cert_type))
        elif days_left < 30:
            expiring_soon.append((domain, days_left, status, in_use, cert_type))
        else:
            ok.append((domain, days_left, status, in_use, cert_type))

if expired:
    print(f'EXPIRED certificates ({len(expired)}):')
    for domain, days, status, in_use, ctype in expired:
        used = 'IN USE' if in_use else 'not in use'
        print(f'  [CRITICAL] {domain}: expired {abs(days)} days ago ({used}, {ctype})')
    print()

if expiring_soon:
    print(f'Expiring within 30 days ({len(expiring_soon)}):')
    for domain, days, status, in_use, ctype in expiring_soon:
        used = 'IN USE' if in_use else 'not in use'
        renewal = detail.get('RenewalSummary', {}).get('RenewalStatus', '-')
        print(f'  [HIGH] {domain}: {days} days left ({used}, {ctype}, renewal: {renewal})')
    print()

print(f'Summary: {len(certs)} certificates — {len(expired)} expired, {len(expiring_soon)} expiring soon, {len(ok)} OK')

if expired:
    in_use_expired = [e for e in expired if e[3]]
    if in_use_expired:
        print(f'CRITICAL: {len(in_use_expired)} expired certificates are still in use!')
"
```

### 10. Macie — Sensitive Data Discovery

```bash
python3 -c "
import boto3

macie = boto3.client('macie2')

try:
    session = macie.get_macie_session()
    status = session.get('status', 'unknown')
    print(f'Macie: {status}')
    print(f'  Created: {session.get(\"createdAt\", \"-\")}')
    print(f'  Updated: {session.get(\"updatedAt\", \"-\")}')
    print(f'  Finding publishing: {session.get(\"findingPublishingFrequency\", \"-\")}')
    print()

    # Get finding summary
    stats = macie.get_finding_statistics(
        GroupBy={'key': 'severity.description'}
    )

    groups = stats.get('countsBySeverity', stats.get('countsByGroup', []))
    if groups:
        print('Findings by severity:')
        for g in groups:
            print(f'  {g.get(\"key\", g.get(\"groupKey\", \"-\"))}: {g[\"count\"]}')
    else:
        print('No Macie findings.')

    # Bucket summary
    try:
        buckets = macie.describe_buckets(criteria={}, maxResults=50)
        bucket_list = buckets.get('buckets', [])

        sensitive = [b for b in bucket_list if b.get('classifiableObjectCount', 0) > 0]
        print(f'\nMonitored buckets: {len(bucket_list)}')
        if sensitive:
            print(f'Buckets with classifiable objects: {len(sensitive)}')
    except Exception:
        pass

except macie.exceptions.AccessDeniedException:
    print('Macie: NOT ENABLED or insufficient permissions')
    print('Note: Macie has a cost — it charges per GB of S3 data scanned')
except Exception as e:
    print(f'Macie: {e}')
"
```

## Domain Knowledge

### Security Service Coverage Matrix

A well-secured AWS account should have all of these enabled:

| Service | Purpose | Impact if Missing |
|---|---|---|
| GuardDuty | Threat detection | No alerting on compromised credentials, crypto mining, data exfiltration |
| Security Hub | Centralized findings + compliance | No unified view, no compliance benchmarks |
| CloudTrail | API audit logging | No audit trail — incident investigation impossible |
| AWS Config | Resource compliance | No drift detection, no compliance tracking |
| VPC Flow Logs | Network traffic logging | No visibility into network activity |
| WAF | Web app protection | No Layer 7 protection for public endpoints |
| Macie | Sensitive data discovery | Unknown PII/sensitive data exposure in S3 |

### Severity Classification

| Severity | Criteria |
|---|---|
| CRITICAL | GuardDuty/Security Hub not enabled, CloudTrail not logging, expired certs in use, KMS key policy open to `*` without conditions |
| HIGH | Active high-severity GuardDuty findings, Config rules failing, no VPC Flow Logs, WAF not protecting public endpoints, secrets not rotated 90+ days |
| MEDIUM | KMS rotation disabled, CloudTrail without log validation, missing data event logging, partial flow log coverage |
| LOW | Informational findings, CloudWatch Logs not configured for CloudTrail (S3 only) |

### Common Gaps

1. **GuardDuty enabled but findings ignored** — Check if there are active findings older than 30 days. Unactioned findings indicate no operational process.
2. **CloudTrail logging but no data events** — Management events are logged by default, but S3 object-level and Lambda invocation events require explicit configuration.
3. **Config enabled but rules not maintained** — Check if rules exist and are actively evaluating. An enabled recorder with no rules provides no compliance value.
4. **WAF exists but default action is Allow** — A WAF with few rules and Allow default provides minimal protection.
5. **Secrets created but never rotated** — Secrets Manager without rotation enabled is just a vault, not a security improvement.

### Cross-Reference with Other Skills

- **IAM permissions for security services** → Use `aws-iam-analyser` to check who can disable GuardDuty, modify CloudTrail, or change Config rules
- **Cost of security services** → Use `aws-cost-analyser` to see spending on GuardDuty, Security Hub, Macie, Config, and CloudTrail
- **Resources without flow logs** → Use `aws-resource-analyser` to cross-check VPC inventory against flow log coverage

### Permissions Required

- `guardduty:ListDetectors`, `guardduty:GetDetector`, `guardduty:ListFindings`, `guardduty:GetFindings`
- `securityhub:DescribeHub`, `securityhub:GetEnabledStandards`, `securityhub:DescribeStandardsControls`, `securityhub:GetFindings`
- `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`
- `config:DescribeConfigurationRecorders`, `config:DescribeComplianceByConfigRule`, `config:GetComplianceDetailsByConfigRule`
- `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`
- `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `wafv2:ListResourcesForWebACL`
- `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`, `kms:ListAliases`
- `secretsmanager:ListSecrets`
- `acm:ListCertificates`, `acm:DescribeCertificate`
- `macie2:GetMacieSession`, `macie2:GetFindingStatistics`, `macie2:DescribeBuckets`

The `SecurityAudit` managed policy covers most of these.

## Output Formatting

- Present findings as **markdown tables** sorted by severity
- Use severity indicators: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Group findings by service (GuardDuty, Security Hub, CloudTrail, etc.)
- For each service, start with enablement status before diving into findings
- Always include **actionable recommendations**
- Show a security posture summary at the end:
  - Services enabled vs not enabled
  - Total findings by severity
  - Top 3 recommendations by impact
- Format: "Security Posture: X/Y services enabled, N critical findings, M high findings"
