---
name: aws-iam-analyser
description: >
  Deep IAM security analysis for AWS accounts. Audit policies for overly permissive
  access, find unused roles and policies, analyze cross-account trust relationships,
  review permission boundaries, evaluate SCPs, trace assume-role chains, and audit
  Identity Center (SSO) configurations. Triggers on: IAM audit, policy review,
  permission analysis, cross-account trust, role trust policy, unused roles, overly
  permissive policies, least privilege, IAM security, SCP analysis, Identity Center,
  SSO audit, access key rotation, privilege escalation.
---

# AWS IAM Analyser

Deep analysis of IAM configurations to enforce least privilege, identify excessive permissions, unused identities, and cross-account trust risks.

## Safety — READ ONLY

This skill is strictly read-only. NEVER create, modify, or delete any IAM resources (users, roles, policies, access keys, permission sets). Only use `list-*`, `get-*`, `describe-*`, and `generate-*` (for reports) API calls. The one exception is `create-analyzer` for IAM Access Analyzer which is a read-only analysis tool — but ONLY suggest this, do NOT run it without explicit user confirmation. If the user asks to take action (e.g., "delete that role", "revoke that policy"), explain the finding and recommend the action but do NOT execute it.

## When to Activate

- User asks about IAM security, policy review, or permissions audit
- Questions about overly permissive policies or `*` actions
- Cross-account trust or role assumption analysis
- Unused roles, policies, or identities cleanup
- Permission boundary or SCP review
- Identity Center (SSO) configuration audit
- Privilege escalation path detection
- Compliance or least privilege assessment

## Prerequisites

Verify AWS access and IAM permissions:

```bash
aws sts get-caller-identity --output json
```

Check if IAM Access Analyzer is enabled (required for some workflows):

```bash
aws accessanalyzer list-analyzers --output json
```

If no analyzer exists, some unused-access workflows won't work. Suggest creating one:

```bash
# Account-level analyzer
aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT
```

Check Organizations access (needed for SCP analysis):

```bash
aws organizations describe-organization --output json 2>/dev/null
```

## Core Workflows

### 1. Policy Analysis — Overly Permissive Policies

#### 1a. Find Policies with Wildcard Actions

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')

# Check customer-managed policies
paginator = iam.get_paginator('list_policies')
risky = []

for page in paginator.paginate(Scope='Local'):
    for policy in page['Policies']:
        version = iam.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        doc = version['PolicyVersion']['Document']
        if isinstance(doc, str):
            doc = json.loads(doc)

        statements = doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            wild_actions = [a for a in actions if a == '*' or a.endswith(':*')]
            if wild_actions and '*' in resources:
                risky.append({
                    'policy': policy['PolicyName'],
                    'arn': policy['Arn'],
                    'actions': wild_actions,
                    'attached': policy['AttachmentCount']
                })

print(f'Found {len(risky)} overly permissive customer-managed policies:\n')
for p in risky:
    attached = f'attached to {p[\"attached\"]} entities' if p['attached'] > 0 else 'NOT attached'
    print(f'  {p[\"policy\"]} ({attached})')
    print(f'    Actions: {p[\"actions\"]}')
    print(f'    Resource: *')
    print()
"
```

#### 1b. Find Inline Policies with Admin-Like Access

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')

# Check all users
for user in iam.list_users()['Users']:
    for policy_name in iam.list_user_policies(UserName=user['UserName'])['PolicyNames']:
        doc = iam.get_user_policy(UserName=user['UserName'], PolicyName=policy_name)['PolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                print(f'USER {user[\"UserName\"]} has inline admin policy: {policy_name}')

# Check all roles
paginator = iam.get_paginator('list_roles')
for page in paginator.paginate():
    for role in page['Roles']:
        try:
            for policy_name in iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']:
                doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)['PolicyDocument']
                if isinstance(doc, str):
                    doc = json.loads(doc)
                for stmt in doc.get('Statement', []):
                    if stmt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                        print(f'ROLE {role[\"RoleName\"]} has inline admin policy: {policy_name}')
        except Exception:
            pass
"
```

#### 1c. Entities with AdministratorAccess Managed Policy

```bash
python3 -c "
import boto3

iam = boto3.client('iam')
admin_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

try:
    entities = iam.list_entities_for_policy(PolicyArn=admin_arn)
    
    users = entities.get('PolicyUsers', [])
    roles = entities.get('PolicyRoles', [])
    groups = entities.get('PolicyGroups', [])
    
    print(f'Entities with AdministratorAccess ({len(users) + len(roles) + len(groups)} total):\n')
    
    if users:
        print('Users:')
        for u in users:
            print(f'  {u[\"UserName\"]}')
    
    if groups:
        print('Groups:')
        for g in groups:
            members = iam.get_group(GroupName=g['GroupName'])['Users']
            member_names = ', '.join(u['UserName'] for u in members) or 'no members'
            print(f'  {g[\"GroupName\"]} ({member_names})')
    
    if roles:
        print('Roles:')
        for r in roles:
            print(f'  {r[\"RoleName\"]}')
except Exception as e:
    print(f'Error: {e}')
"
```

#### 1d. Dangerous Permission Patterns

Detect policies that allow privilege escalation:

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')

# Actions that can lead to privilege escalation
escalation_actions = [
    'iam:CreatePolicy', 'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
    'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy',
    'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy',
    'iam:CreateRole', 'iam:UpdateAssumeRolePolicy',
    'iam:AddUserToGroup',
    'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
    'iam:CreateAccessKey',
    'iam:PassRole',
    'sts:AssumeRole',
    'lambda:CreateFunction', 'lambda:InvokeFunction', 'lambda:UpdateFunctionCode',
    'ec2:RunInstances',  # with iam:PassRole = escalation
    'cloudformation:CreateStack',  # with iam:PassRole = escalation
]

def check_policy_doc(doc, entity_name, entity_type, policy_name):
    if isinstance(doc, str):
        doc = json.loads(doc)
    statements = doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    
    found = []
    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action == '*':
                found.append('*')
                break
            for esc in escalation_actions:
                if action == esc or (action.endswith(':*') and esc.startswith(action[:-1])):
                    found.append(esc)
    
    if found:
        print(f'{entity_type} {entity_name} via {policy_name}:')
        for a in set(found):
            print(f'  - {a}')

# Scan customer-managed policies that are attached
paginator = iam.get_paginator('list_policies')
for page in paginator.paginate(Scope='Local', OnlyAttached=True):
    for policy in page['Policies']:
        version = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
        doc = version['PolicyVersion']['Document']
        
        # Find who it's attached to
        entities = iam.list_entities_for_policy(PolicyArn=policy['Arn'])
        for u in entities.get('PolicyUsers', []):
            check_policy_doc(doc, u['UserName'], 'USER', policy['PolicyName'])
        for r in entities.get('PolicyRoles', []):
            check_policy_doc(doc, r['RoleName'], 'ROLE', policy['PolicyName'])

print('\nNote: PassRole + compute service (Lambda/EC2/CF) = privilege escalation path')
"
```

### 2. Unused Roles and Policies

#### 2a. Roles Not Used Recently (via Access Advisor)

```bash
python3 -c "
import boto3, datetime

iam = boto3.client('iam')
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)

paginator = iam.get_paginator('list_roles')
unused = []

for page in paginator.paginate():
    for role in page['Roles']:
        # Skip AWS service-linked roles
        if role['Path'].startswith('/aws-service-role/'):
            continue
        
        last_used = role.get('RoleLastUsed', {}).get('LastUsedDate')
        if last_used is None:
            age = (datetime.datetime.now(datetime.timezone.utc) - role['CreateDate']).days
            unused.append((role['RoleName'], 'NEVER used', age))
        elif last_used < cutoff:
            days_since = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
            unused.append((role['RoleName'], f'last used {days_since} days ago', None))

unused.sort(key=lambda x: x[1])
print(f'Found {len(unused)} roles unused for 90+ days:\n')
for name, status, age in unused:
    extra = f' (created {age} days ago)' if age else ''
    print(f'  {name}: {status}{extra}')
"
```

#### 2b. Unattached Customer-Managed Policies

```bash
aws iam list-policies \
  --scope Local \
  --only-attached false \
  --query 'Policies[?AttachmentCount==`0`].{Name:PolicyName,Arn:Arn,Created:CreateDate}' \
  --output table
```

#### 2c. Unused Access via IAM Access Analyzer

If Access Analyzer is enabled with unused access analysis:

```bash
python3 -c "
import boto3, json

analyzer = boto3.client('accessanalyzer')
analyzers = analyzer.list_analyzers(Type='ACCOUNT')['analyzers']

if not analyzers:
    print('No IAM Access Analyzer found. Create one for unused access findings.')
    print('Run: aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT')
else:
    arn = analyzers[0]['arn']
    paginator = analyzer.get_paginator('list_findings_v2')
    
    findings = []
    for page in paginator.paginate(analyzerArn=arn):
        for finding in page['findings']:
            if finding['status'] == 'ACTIVE':
                findings.append(finding)
    
    print(f'Active Access Analyzer findings: {len(findings)}\n')
    
    by_type = {}
    for f in findings:
        t = f['findingType']
        by_type.setdefault(t, []).append(f)
    
    for ftype, items in sorted(by_type.items()):
        print(f'{ftype}: {len(items)}')
        for item in items[:5]:
            print(f'  {item[\"resource\"]} - {item.get(\"resourceType\", \"\")}')
        if len(items) > 5:
            print(f'  ... and {len(items) - 5} more')
        print()
"
```

### 3. Cross-Account Trust Analysis

#### 3a. Roles Trusting External Accounts

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')
sts = boto3.client('sts')
own_account = sts.get_caller_identity()['Account']

paginator = iam.get_paginator('list_roles')
external_trusts = []

for page in paginator.paginate():
    for role in page['Roles']:
        doc = role['AssumeRolePolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            
            principals = stmt.get('Principal', {})
            if isinstance(principals, str):
                principals = {'AWS': [principals]}
            
            aws_principals = principals.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            for principal in aws_principals:
                if principal == '*':
                    conditions = stmt.get('Condition', {})
                    external_trusts.append({
                        'role': role['RoleName'],
                        'principal': '* (ANY AWS account)',
                        'condition': json.dumps(conditions) if conditions else 'NONE — DANGEROUS',
                        'severity': 'CRITICAL' if not conditions else 'HIGH'
                    })
                elif ':root' in principal or ':user/' in principal or ':role/' in principal:
                    account_id = principal.split(':')[4] if ':' in principal else 'unknown'
                    if account_id != own_account:
                        conditions = stmt.get('Condition', {})
                        external_trusts.append({
                            'role': role['RoleName'],
                            'principal': principal,
                            'condition': json.dumps(conditions) if conditions else 'none',
                            'severity': 'HIGH' if not conditions else 'MEDIUM'
                        })
            
            # Check for Service principals (normal, but worth listing)
            service_principals = principals.get('Service', [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]

# Sort by severity
order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
external_trusts.sort(key=lambda x: order.get(x['severity'], 3))

print(f'Found {len(external_trusts)} cross-account trust relationships:\n')
for t in external_trusts:
    print(f'[{t[\"severity\"]}] {t[\"role\"]}')
    print(f'  Trusted: {t[\"principal\"]}')
    print(f'  Condition: {t[\"condition\"]}')
    print()
"
```

#### 3b. Roles Trusting Third-Party Services

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')
paginator = iam.get_paginator('list_roles')

third_party = []
for page in paginator.paginate():
    for role in page['Roles']:
        doc = role['AssumeRolePolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        
        for stmt in doc.get('Statement', []):
            principals = stmt.get('Principal', {})
            if isinstance(principals, str):
                continue
            
            federated = principals.get('Federated', [])
            if isinstance(federated, str):
                federated = [federated]
            
            for fed in federated:
                if 'saml-provider' not in fed.lower() and 'cognito' not in fed.lower():
                    conditions = stmt.get('Condition', {})
                    third_party.append({
                        'role': role['RoleName'],
                        'federated': fed,
                        'condition': json.dumps(conditions)[:80] if conditions else 'NONE'
                    })

print(f'Found {len(third_party)} federated trust relationships:\n')
for t in third_party:
    print(f'  {t[\"role\"]}')
    print(f'    Federated: {t[\"federated\"]}')
    print(f'    Condition: {t[\"condition\"]}')
    print()
"
```

### 4. Permission Boundaries

#### 4a. Audit Permission Boundary Usage

```bash
python3 -c "
import boto3

iam = boto3.client('iam')

# Check users
users_with_boundary = []
users_without = []
for user in iam.list_users()['Users']:
    detail = iam.get_user(UserName=user['UserName'])['User']
    boundary = detail.get('PermissionsBoundary')
    if boundary:
        users_with_boundary.append((user['UserName'], boundary['PermissionsBoundaryArn']))
    else:
        users_without.append(user['UserName'])

# Check roles (excluding service-linked)
roles_with_boundary = []
roles_without = []
paginator = iam.get_paginator('list_roles')
for page in paginator.paginate():
    for role in page['Roles']:
        if role['Path'].startswith('/aws-service-role/'):
            continue
        boundary = role.get('PermissionsBoundary')
        if boundary:
            roles_with_boundary.append((role['RoleName'], boundary['PermissionsBoundaryArn']))
        else:
            roles_without.append(role['RoleName'])

print('=== Permission Boundary Summary ===\n')
print(f'Users:  {len(users_with_boundary)} with boundary, {len(users_without)} without')
print(f'Roles:  {len(roles_with_boundary)} with boundary, {len(roles_without)} without')

if users_with_boundary:
    print('\nUsers with boundaries:')
    for name, arn in users_with_boundary:
        print(f'  {name}: {arn.split(\"/\")[-1]}')

if roles_with_boundary:
    print('\nRoles with boundaries:')
    for name, arn in roles_with_boundary[:10]:
        print(f'  {name}: {arn.split(\"/\")[-1]}')
    if len(roles_with_boundary) > 10:
        print(f'  ... and {len(roles_with_boundary) - 10} more')

if users_without:
    print(f'\nUsers WITHOUT boundary ({len(users_without)}):')
    for name in users_without:
        print(f'  {name}')
"
```

### 5. Service Control Policies (Organizations)

#### 5a. List and Analyze SCPs

```bash
python3 -c "
import boto3, json

org = boto3.client('organizations')

# List all SCPs
policies = org.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
print(f'Found {len(policies)} SCPs:\n')

for policy in policies:
    pid = policy['Id']
    name = policy['Name']
    
    # Get policy content
    detail = org.describe_policy(PolicyId=pid)
    doc = json.loads(detail['Policy']['Content'])
    
    # Get targets
    targets = org.list_targets_for_policy(PolicyId=pid)['Targets']
    target_names = [f'{t[\"Name\"]} ({t[\"Type\"]})' for t in targets]
    
    print(f'{name} ({pid})')
    print(f'  Attached to: {', '.join(target_names) if target_names else \"not attached\"}')
    
    statements = doc.get('Statement', [])
    for stmt in statements:
        effect = stmt.get('Effect', '')
        actions = stmt.get('Action', stmt.get('NotAction', []))
        if isinstance(actions, str):
            actions = [actions]
        action_summary = actions[:3]
        if len(actions) > 3:
            action_summary.append(f'... +{len(actions) - 3} more')
        
        resources = stmt.get('Resource', stmt.get('NotResource', '*'))
        conditions = 'yes' if stmt.get('Condition') else 'no'
        
        print(f'  {effect}: {action_summary}')
        print(f'    Resource: {resources}, Conditions: {conditions}')
    print()
"
```

#### 5b. Check SCP Inheritance on an Account

```bash
python3 -c "
import boto3, json

org = boto3.client('organizations')

# Get all accounts
accounts = org.list_accounts()['Accounts']

for acct in accounts[:5]:  # Limit to first 5, adjust as needed
    print(f'=== {acct[\"Name\"]} ({acct[\"Id\"]}) ===')
    
    # Get SCPs directly attached to this account
    direct = org.list_policies_for_target(TargetId=acct['Id'], Filter='SERVICE_CONTROL_POLICY')['Policies']
    
    # Get parent OUs to find inherited SCPs
    parents = org.list_parents(ChildId=acct['Id'])['Parents']
    
    print(f'  Direct SCPs: {[p[\"Name\"] for p in direct]}')
    
    for parent in parents:
        if parent['Type'] == 'ORGANIZATIONAL_UNIT':
            ou_policies = org.list_policies_for_target(TargetId=parent['Id'], Filter='SERVICE_CONTROL_POLICY')['Policies']
            ou_detail = org.describe_organizational_unit(OrganizationalUnitId=parent['Id'])
            print(f'  Inherited from OU {ou_detail[\"OrganizationalUnit\"][\"Name\"]}: {[p[\"Name\"] for p in ou_policies]}')
        elif parent['Type'] == 'ROOT':
            root_policies = org.list_policies_for_target(TargetId=parent['Id'], Filter='SERVICE_CONTROL_POLICY')['Policies']
            print(f'  Inherited from root: {[p[\"Name\"] for p in root_policies]}')
    print()
"
```

### 6. Last Accessed Analysis

#### 6a. Service Last Accessed for a Role

Identify which services a role actually uses vs what it has access to:

```bash
python3 -c "
import boto3, time, datetime

iam = boto3.client('iam')
role_name = input('Role name to analyze: ') if False else 'ROLE_NAME_HERE'

# Generate the report
role_arn = iam.get_role(RoleName=role_name)['Role']['Arn']
job_id = iam.generate_service_last_accessed_details(Arn=role_arn)['JobId']

# Wait for completion
while True:
    result = iam.get_service_last_accessed_details(JobId=job_id)
    if result['JobStatus'] == 'COMPLETED':
        break
    time.sleep(1)

services = result['ServicesLastAccessed']
accessed = [(s['ServiceName'], s.get('LastAuthenticated'), s['TotalAuthenticatedEntities']) 
            for s in services if s.get('LastAuthenticated')]
not_accessed = [(s['ServiceName'],) for s in services if not s.get('LastAuthenticated')]

accessed.sort(key=lambda x: x[1], reverse=True)

print(f'Role: {role_name}')
print(f'Has access to {len(services)} services, actually used {len(accessed)}\n')

print('Recently used services:')
for name, last, count in accessed[:15]:
    days_ago = (datetime.datetime.now(datetime.timezone.utc) - last).days
    print(f'  {name}: {days_ago} days ago ({count} entities)')

print(f'\nUnused services ({len(not_accessed)}):')
for (name,) in not_accessed[:10]:
    print(f'  {name}')
if len(not_accessed) > 10:
    print(f'  ... and {len(not_accessed) - 10} more')

print(f'\nRecommendation: Remove access to {len(not_accessed)} unused services for least privilege')
"
```

Replace `ROLE_NAME_HERE` with the actual role name. When using this workflow, ask the user which role to analyze.

#### 6b. Bulk Last-Accessed Audit for All Roles

```bash
python3 -c "
import boto3, time, datetime

iam = boto3.client('iam')
paginator = iam.get_paginator('list_roles')

print(f'{'Role':<40} {'Services Granted':<18} {'Services Used':<15} {'Excess':<10}')
print('-' * 83)

for page in paginator.paginate():
    for role in page['Roles']:
        if role['Path'].startswith('/aws-service-role/'):
            continue
        
        try:
            job_id = iam.generate_service_last_accessed_details(Arn=role['Arn'])['JobId']
            
            while True:
                result = iam.get_service_last_accessed_details(JobId=job_id)
                if result['JobStatus'] in ('COMPLETED', 'FAILED'):
                    break
                time.sleep(0.5)
            
            if result['JobStatus'] == 'COMPLETED':
                total = len(result['ServicesLastAccessed'])
                used = sum(1 for s in result['ServicesLastAccessed'] if s.get('LastAuthenticated'))
                excess = total - used
                
                flag = ' << review' if excess > 10 and used > 0 else ''
                flag = ' << NEVER USED' if used == 0 else flag
                print(f'{role[\"RoleName\"]:<40} {total:<18} {used:<15} {excess:<10}{flag}')
        except Exception:
            pass
"
```

Note: This is slow for accounts with many roles due to API calls per role. Use selectively.

### 7. Assume Role Chain Analysis

#### 7a. Map Who Can Assume Which Roles

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')
sts = boto3.client('sts')
own_account = sts.get_caller_identity()['Account']

paginator = iam.get_paginator('list_roles')
trust_map = []

for page in paginator.paginate():
    for role in page['Roles']:
        if role['Path'].startswith('/aws-service-role/'):
            continue
        
        doc = role['AssumeRolePolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            
            principals = stmt.get('Principal', {})
            if isinstance(principals, str):
                principals = {'AWS': [principals]}
            
            aws_principals = principals.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            for principal in aws_principals:
                trust_map.append({
                    'target_role': role['RoleName'],
                    'trusted_by': principal,
                    'conditions': bool(stmt.get('Condition'))
                })

# Group by who trusts whom
print('=== Role Trust Map ===\n')
by_target = {}
for t in trust_map:
    by_target.setdefault(t['target_role'], []).append(t)

for target, trusts in sorted(by_target.items()):
    print(f'{target}:')
    for t in trusts:
        cond = ' (with conditions)' if t['conditions'] else ''
        print(f'  <- {t[\"trusted_by\"]}{cond}')
    print()
"
```

#### 7b. Detect Role Chaining Paths

Roles that trust other roles in the same account — potential escalation paths:

```bash
python3 -c "
import boto3, json

iam = boto3.client('iam')
sts = boto3.client('sts')
own_account = sts.get_caller_identity()['Account']

paginator = iam.get_paginator('list_roles')
role_names = set()
trust_edges = []

for page in paginator.paginate():
    for role in page['Roles']:
        if role['Path'].startswith('/aws-service-role/'):
            continue
        role_names.add(role['RoleName'])
        
        doc = role['AssumeRolePolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            principals = stmt.get('Principal', {})
            if isinstance(principals, str):
                principals = {'AWS': [principals]}
            
            for p in principals.get('AWS', []) if isinstance(principals.get('AWS'), list) else [principals.get('AWS', '')]:
                if f'arn:aws:iam::{own_account}:role/' in str(p):
                    source_role = str(p).split('/')[-1]
                    if source_role in role_names or True:
                        trust_edges.append((source_role, role['RoleName']))

# Find chains (depth-limited BFS)
from collections import defaultdict, deque
graph = defaultdict(list)
for src, dst in trust_edges:
    graph[src].append(dst)

print('=== Role Chaining Paths (same account) ===\n')
chains_found = 0
for start in graph:
    queue = deque([(start, [start])])
    visited = {start}
    while queue:
        current, path = queue.popleft()
        for neighbor in graph.get(current, []):
            if neighbor in visited:
                if neighbor == start and len(path) > 1:
                    print(f'CIRCULAR: {\" -> \".join(path + [neighbor])}')
                    chains_found += 1
                continue
            new_path = path + [neighbor]
            if len(new_path) > 1:
                print(f'Chain: {\" -> \".join(new_path)}')
                chains_found += 1
            if len(new_path) < 4:  # Limit depth
                visited.add(neighbor)
                queue.append((neighbor, new_path))

if chains_found == 0:
    print('No role chaining paths found.')
"
```

### 8. Identity Center (SSO) Audit

#### 8a. List Permission Sets and Assignments

```bash
python3 -c "
import boto3

sso = boto3.client('sso-admin')
identity_store = boto3.client('identitystore')

# Get SSO instance
instances = sso.list_instances()['Instances']
if not instances:
    print('No Identity Center instance found.')
    exit()

instance_arn = instances[0]['InstanceArn']
identity_store_id = instances[0]['IdentityStoreId']

# List permission sets
paginator = sso.get_paginator('list_permission_sets')
for page in paginator.paginate(InstanceArn=instance_arn):
    for ps_arn in page['PermissionSets']:
        ps = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)['PermissionSet']
        
        print(f'{ps[\"Name\"]} (session: {ps.get(\"SessionDuration\", \"?\")})')
        print(f'  Description: {ps.get(\"Description\", \"-\")}')
        
        # Get managed policies
        policies = sso.list_managed_policies_in_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )['AttachedManagedPolicies']
        if policies:
            print(f'  Managed policies: {[p[\"Name\"] for p in policies]}')
        
        # Get inline policy
        try:
            inline = sso.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )['InlinePolicy']
            if inline:
                print(f'  Has inline policy ({len(inline)} chars)')
        except:
            pass
        
        # Get account assignments
        try:
            accounts = sso.list_accounts_for_provisioned_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )['AccountIds']
            print(f'  Provisioned to {len(accounts)} accounts: {accounts[:5]}')
        except:
            pass
        
        print()
"
```

#### 8b. Find Overly Broad SSO Assignments

```bash
python3 -c "
import boto3

sso = boto3.client('sso-admin')
org = boto3.client('organizations')

instances = sso.list_instances()['Instances']
if not instances:
    print('No Identity Center instance found.')
    exit()

instance_arn = instances[0]['InstanceArn']
accounts = org.list_accounts()['Accounts']

# Check which permission sets have admin-like policies
paginator = sso.get_paginator('list_permission_sets')
admin_ps = []

for page in paginator.paginate(InstanceArn=instance_arn):
    for ps_arn in page['PermissionSets']:
        policies = sso.list_managed_policies_in_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )['AttachedManagedPolicies']
        
        admin_policies = [p for p in policies if 'Admin' in p['Name'] or 'FullAccess' in p['Name']]
        if admin_policies:
            ps = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)['PermissionSet']
            
            # Count assignments
            assigned_accounts = sso.list_accounts_for_provisioned_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            ).get('AccountIds', [])
            
            admin_ps.append({
                'name': ps['Name'],
                'policies': [p['Name'] for p in admin_policies],
                'account_count': len(assigned_accounts)
            })

print('Permission sets with admin-like policies:\n')
for ps in admin_ps:
    pct = (ps['account_count'] / len(accounts)) * 100 if accounts else 0
    flag = ' << BROAD' if pct > 50 else ''
    print(f'{ps[\"name\"]}: {ps[\"policies\"]}')
    print(f'  Assigned to {ps[\"account_count\"]}/{len(accounts)} accounts ({pct:.0f}%){flag}')
    print()
"
```

## Domain Knowledge

### Privilege Escalation Patterns

These action combinations allow a user to elevate their own privileges:

| Pattern | Actions Required | Risk |
|---|---|---|
| Policy attachment | `iam:AttachUserPolicy` or `iam:AttachRolePolicy` | Attach AdministratorAccess to self |
| Inline policy | `iam:PutUserPolicy` or `iam:PutRolePolicy` | Write admin inline policy |
| Policy version | `iam:CreatePolicyVersion` | Replace existing policy content |
| Role assumption | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Modify trust, then assume admin role |
| PassRole + Lambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin role |
| PassRole + EC2 | `iam:PassRole` + `ec2:RunInstances` | Launch instance with admin role |
| PassRole + CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` | Deploy stack with admin role |
| Group manipulation | `iam:AddUserToGroup` | Add self to admin group |
| Access key creation | `iam:CreateAccessKey` | Create keys for another user |

### Trust Policy Pitfalls

- `Principal: "*"` without conditions = **any AWS account** can assume the role
- `Principal: {"AWS": "arn:aws:iam::123456789012:root"}` = any identity in that account
- Conditions on `sts:ExternalId` help prevent confused deputy, but ExternalId is not secret
- `sts:SourceIdentity` and `sts:RoleSessionName` conditions add traceability but not security

### SCP Gotchas

- SCPs don't grant permissions, they only restrict them (deny-list or allow-list)
- The `FullAWSAccess` SCP must be attached somewhere in the hierarchy or nothing works
- SCPs don't affect the management account — only member accounts
- SCPs don't affect service-linked roles
- Deny SCPs override any allow in IAM policies

### Permission Boundary vs SCP

| Feature | Permission Boundary | SCP |
|---|---|---|
| Scope | Single user or role | OU or account |
| Who sets it | IAM admin | Org admin |
| Affects management account | Yes | No |
| Affects service-linked roles | No | No |
| Can grant permissions | No (limits only) | No (limits only) |

### Cross-Reference with Other Skills

- Found roles with excessive permissions? → Use `aws-cost-analyser` to check if the associated resources are worth the security risk
- Found unused roles attached to resources? → Use `aws-resource-analyser` to check if those resources are also idle

## Output Formatting

- Use severity levels: `CRITICAL` (open trust, admin wildcard), `HIGH` (escalation path, broad access), `MEDIUM` (unused access, missing boundary), `LOW` (informational)
- Sort findings by severity, then by blast radius (number of affected entities)
- Always include **remediation steps** (which action to take: restrict policy, delete role, add condition, etc.)
- For policy analysis, show the specific problematic statement, not the full policy
- For trust relationships, show the trust graph as arrow notation: `AccountA/RoleX -> AccountB/RoleY`
- Summary at the end: "Found X critical, Y high, Z medium findings across N roles/policies"
