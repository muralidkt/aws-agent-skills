---
name: aws-bedrock-analyser
description: >
  Analyze AWS Bedrock usage, costs, and security posture. Triggers on: Bedrock costs,
  model invocation usage, provisioned throughput, foundation model access, Bedrock
  guardrails, knowledge bases, Bedrock agents, model logging, token consumption,
  Bedrock inventory, Bedrock security audit, generative AI costs, LLM usage.
---

# AWS Bedrock Analyser

Analyze AWS Bedrock configurations, usage patterns, costs, and security posture. Covers foundation model access, provisioned throughput, guardrails, knowledge bases, agents, and invocation logging.

## Safety — READ ONLY

This skill is strictly read-only. NEVER create, modify, or delete any Bedrock resources (models, guardrails, knowledge bases, agents, provisioned throughput). Only use `list-*`, `get-*`, `describe-*` API calls and CloudWatch metric reads. If the user asks to take action (e.g., "delete that knowledge base", "create a guardrail"), explain the finding and recommend the action but do NOT execute it.

## When to Activate

- User asks about Bedrock usage, costs, or what models are in use
- Questions about provisioned throughput utilization or waste
- Guardrail configuration review or coverage gaps
- Knowledge base or agent inventory
- Bedrock security audit: model access, logging, permissions
- "What Bedrock resources do I have?" or "How much is Bedrock costing me?"
- Token consumption or invocation pattern analysis

## Prerequisites

Verify AWS access:

```bash
aws sts get-caller-identity --output json
```

Check if Bedrock is available in the current region:

```bash
aws bedrock list-foundation-models --query 'modelSummaries[0].modelId' --output text 2>/dev/null
```

If this fails, Bedrock may not be available in the current region. Check supported regions:

```bash
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

Common Bedrock regions: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-northeast-1`.

Get the current region:

```bash
aws configure get region
```

## Core Workflows

### 1. Foundation Model Access

#### 1a. Available Foundation Models

```bash
aws bedrock list-foundation-models \
  --query 'modelSummaries[].{Id:modelId,Name:modelName,Provider:providerName,Input:inputModalities,Output:outputModalities,Streaming:responseStreamingSupported}' \
  --output table
```

#### 1b. Models Enabled for Use (Custom Model Access)

```bash
python3 -c "
import boto3

bedrock = boto3.client('bedrock')

# List model access permissions
try:
    models = bedrock.list_foundation_models()['modelSummaries']

    by_provider = {}
    for m in models:
        provider = m['providerName']
        by_provider.setdefault(provider, []).append(m)

    for provider, items in sorted(by_provider.items()):
        print(f'{provider} ({len(items)} models):')
        for m in items:
            modalities = '/'.join(m.get('inputModalities', []))
            print(f'  {m[\"modelId\"]}  [{modalities}]')
        print()

    print(f'Total: {len(models)} foundation models available')
except Exception as e:
    print(f'Error: {e}')
"
```

#### 1c. Custom Models

```bash
aws bedrock list-custom-models \
  --query 'modelSummaries[].{Name:modelName,BaseModel:baseModelIdentifier,Created:creationTime,Status:modelStatus}' \
  --output table 2>/dev/null || echo "No custom models found"
```

### 2. Provisioned Throughput Analysis

#### 2a. List Provisioned Throughput

```bash
aws bedrock list-provisioned-model-throughputs \
  --query 'provisionedModelSummaries[].{Name:provisionedModelName,Model:modelId,Status:status,Commitment:commitmentDuration,Units:provisionedModelArn,Created:creationTime}' \
  --output table 2>/dev/null || echo "No provisioned throughput found"
```

#### 2b. Provisioned Throughput Utilization

```bash
python3 -c "
import boto3, datetime

bedrock = boto3.client('bedrock')
cw = boto3.client('cloudwatch')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=7)

try:
    provisioned = bedrock.list_provisioned_model_throughputs().get('provisionedModelSummaries', [])

    if not provisioned:
        print('No provisioned throughput found.')
    else:
        print(f'{'Name':<30} {'Model':<35} {'Status':<12} {'Commitment':<15}')
        print('-' * 92)

        for pt in provisioned:
            name = pt['provisionedModelName']
            model = pt.get('modelId', '-')[:35]
            status = pt['status']
            commitment = pt.get('commitmentDuration', 'none')

            # Check invocation metrics
            metrics = cw.get_metric_statistics(
                Namespace='AWS/Bedrock',
                MetricName='Invocations',
                Dimensions=[{'Name': 'ModelId', 'Value': pt.get('modelArn', pt.get('provisionedModelArn', ''))}],
                StartTime=start, EndTime=end,
                Period=86400 * 7,
                Statistics=['Sum']
            )
            invocations = metrics['Datapoints'][0]['Sum'] if metrics['Datapoints'] else 0

            flag = ' << ZERO USAGE' if invocations == 0 and status == 'InService' else ''
            print(f'{name:<30} {model:<35} {status:<12} {commitment:<15}{flag}')

            if invocations == 0 and status == 'InService':
                print(f'  WARNING: Provisioned throughput with zero invocations in 7 days — wasted commitment')

except Exception as e:
    print(f'Error: {e}')
"
```

### 3. Guardrails Review

#### 3a. List Guardrails

```bash
python3 -c "
import boto3, json

bedrock = boto3.client('bedrock')

try:
    guardrails = bedrock.list_guardrails().get('guardrails', [])

    if not guardrails:
        print('No guardrails configured.')
        print('Recommendation: Create guardrails to enforce content filtering and topic restrictions.')
    else:
        print(f'Found {len(guardrails)} guardrails:\n')
        for g in guardrails:
            print(f'{g[\"name\"]} (v{g.get(\"version\", \"?\")})')
            print(f'  ID: {g[\"id\"]}')
            print(f'  Status: {g[\"status\"]}')
            print(f'  Created: {g.get(\"createdAt\", \"-\")}')
            print(f'  Updated: {g.get(\"updatedAt\", \"-\")}')
            print()

except Exception as e:
    print(f'Error: {e}')
"
```

#### 3b. Guardrail Configuration Detail

```bash
python3 -c "
import boto3, json

bedrock = boto3.client('bedrock')

guardrails = bedrock.list_guardrails().get('guardrails', [])

for g in guardrails:
    detail = bedrock.get_guardrail(guardrailIdentifier=g['id'])

    print(f'=== {detail[\"name\"]} ===')
    print(f'  Status: {detail[\"status\"]}')

    # Content filters
    content_policy = detail.get('contentPolicy', {})
    filters = content_policy.get('filters', [])
    if filters:
        print(f'  Content filters ({len(filters)}):')
        for f in filters:
            print(f'    {f[\"type\"]}: input={f.get(\"inputStrength\", \"-\")}, output={f.get(\"outputStrength\", \"-\")}')
    else:
        print(f'  Content filters: NONE — no content filtering active')

    # Topic policy
    topic_policy = detail.get('topicPolicy', {})
    topics = topic_policy.get('topics', [])
    if topics:
        print(f'  Denied topics ({len(topics)}):')
        for t in topics:
            print(f'    {t[\"name\"]}: {t.get(\"definition\", \"-\")[:60]}')

    # Word policy
    word_policy = detail.get('wordPolicy', {})
    words = word_policy.get('words', [])
    managed = word_policy.get('managedWordLists', [])
    if words or managed:
        print(f'  Word filters: {len(words)} custom words, {len(managed)} managed lists')

    # Sensitive info policy
    sensitive_policy = detail.get('sensitiveInformationPolicy', {})
    pii = sensitive_policy.get('piiEntities', [])
    regexes = sensitive_policy.get('regexes', [])
    if pii or regexes:
        print(f'  PII filters: {len(pii)} PII types, {len(regexes)} regex patterns')
    else:
        print(f'  PII filters: NONE')

    # Contextual grounding
    grounding = detail.get('contextualGroundingPolicy', {})
    if grounding:
        print(f'  Contextual grounding: enabled')
    
    print()
"
```

#### 3c. Guardrail Coverage Audit

```bash
python3 -c "
import boto3

bedrock = boto3.client('bedrock')
guardrails = bedrock.list_guardrails().get('guardrails', [])

checks = {
    'Content filtering': False,
    'Topic restrictions': False,
    'PII detection': False,
    'Word filtering': False,
    'Contextual grounding': False,
}

for g in guardrails:
    detail = bedrock.get_guardrail(guardrailIdentifier=g['id'])

    if detail.get('contentPolicy', {}).get('filters'):
        checks['Content filtering'] = True
    if detail.get('topicPolicy', {}).get('topics'):
        checks['Topic restrictions'] = True
    if detail.get('sensitiveInformationPolicy', {}).get('piiEntities') or \
       detail.get('sensitiveInformationPolicy', {}).get('regexes'):
        checks['PII detection'] = True
    if detail.get('wordPolicy', {}).get('words') or \
       detail.get('wordPolicy', {}).get('managedWordLists'):
        checks['Word filtering'] = True
    if detail.get('contextualGroundingPolicy'):
        checks['Contextual grounding'] = True

print('Guardrail Coverage Audit:\n')
for check, enabled in checks.items():
    status = 'COVERED' if enabled else 'MISSING'
    print(f'  {check}: {status}')

missing = [k for k, v in checks.items() if not v]
if missing:
    print(f'\nRecommendation: Configure guardrails for: {\", \".join(missing)}')
else:
    print(f'\nAll guardrail categories covered.')
"
```

### 4. Knowledge Bases

#### 4a. List Knowledge Bases

```bash
python3 -c "
import boto3

bedrock_agent = boto3.client('bedrock-agent')

try:
    kbs = bedrock_agent.list_knowledge_bases().get('knowledgeBaseSummaries', [])

    if not kbs:
        print('No knowledge bases found.')
    else:
        print(f'Found {len(kbs)} knowledge bases:\n')
        for kb in kbs:
            print(f'{kb[\"name\"]}')
            print(f'  ID: {kb[\"knowledgeBaseId\"]}')
            print(f'  Status: {kb[\"status\"]}')
            print(f'  Updated: {kb.get(\"updatedAt\", \"-\")}')
            print()

except Exception as e:
    print(f'Error: {e}')
"
```

#### 4b. Knowledge Base Detail with Data Sources

```bash
python3 -c "
import boto3

bedrock_agent = boto3.client('bedrock-agent')

kbs = bedrock_agent.list_knowledge_bases().get('knowledgeBaseSummaries', [])

for kb in kbs:
    kb_id = kb['knowledgeBaseId']
    detail = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)['knowledgeBase']

    print(f'=== {detail[\"name\"]} ===')
    print(f'  Status: {detail[\"status\"]}')
    print(f'  Role: {detail.get(\"roleArn\", \"-\").split(\"/\")[-1]}')

    # Storage config
    storage = detail.get('storageConfiguration', {})
    storage_type = storage.get('type', '-')
    print(f'  Vector store: {storage_type}')

    # Embedding model
    kb_config = detail.get('knowledgeBaseConfiguration', {})
    vector_config = kb_config.get('vectorKnowledgeBaseConfiguration', {})
    embedding_model = vector_config.get('embeddingModelArn', '-').split('/')[-1]
    print(f'  Embedding model: {embedding_model}')

    # Data sources
    try:
        sources = bedrock_agent.list_data_sources(knowledgeBaseId=kb_id).get('dataSourceSummaries', [])
        print(f'  Data sources ({len(sources)}):')
        for src in sources:
            print(f'    {src[\"name\"]}: {src[\"status\"]}')
    except Exception:
        pass

    print()
"
```

### 5. Agents Inventory

#### 5a. List Bedrock Agents

```bash
python3 -c "
import boto3

bedrock_agent = boto3.client('bedrock-agent')

try:
    agents = bedrock_agent.list_agents().get('agentSummaries', [])

    if not agents:
        print('No Bedrock agents found.')
    else:
        print(f'Found {len(agents)} agents:\n')
        for a in agents:
            print(f'{a.get(\"agentName\", \"-\")}')
            print(f'  ID: {a[\"agentId\"]}')
            print(f'  Status: {a[\"agentStatus\"]}')
            print(f'  Updated: {a.get(\"updatedAt\", \"-\")}')
            print()

except Exception as e:
    print(f'Error: {e}')
"
```

#### 5b. Agent Detail with Action Groups and Knowledge Bases

```bash
python3 -c "
import boto3

bedrock_agent = boto3.client('bedrock-agent')

agents = bedrock_agent.list_agents().get('agentSummaries', [])

for a in agents:
    agent_id = a['agentId']
    detail = bedrock_agent.get_agent(agentId=agent_id)['agent']

    print(f'=== {detail.get(\"agentName\", \"-\")} ===')
    print(f'  Status: {detail[\"agentStatus\"]}')
    print(f'  Model: {detail.get(\"foundationModel\", \"-\")}')
    print(f'  Role: {detail.get(\"agentResourceRoleArn\", \"-\").split(\"/\")[-1]}')
    print(f'  Idle timeout: {detail.get(\"idleSessionTTLInSeconds\", \"-\")}s')

    instruction = detail.get('instruction', '')
    if instruction:
        print(f'  Instruction: {instruction[:100]}...' if len(instruction) > 100 else f'  Instruction: {instruction}')

    # Action groups
    try:
        action_groups = bedrock_agent.list_agent_action_groups(
            agentId=agent_id,
            agentVersion='DRAFT'
        ).get('actionGroupSummaries', [])
        if action_groups:
            print(f'  Action groups ({len(action_groups)}):')
            for ag in action_groups:
                print(f'    {ag[\"actionGroupName\"]}: {ag[\"actionGroupState\"]}')
    except Exception:
        pass

    # Associated knowledge bases
    try:
        agent_kbs = bedrock_agent.list_agent_knowledge_bases(
            agentId=agent_id,
            agentVersion='DRAFT'
        ).get('agentKnowledgeBaseSummaries', [])
        if agent_kbs:
            print(f'  Knowledge bases ({len(agent_kbs)}):')
            for akb in agent_kbs:
                print(f'    {akb[\"knowledgeBaseId\"]}: {akb[\"knowledgeBaseState\"]}')
    except Exception:
        pass

    print()
"
```

### 6. Invocation Logging & Security

#### 6a. Check Model Invocation Logging

```bash
python3 -c "
import boto3, json

bedrock = boto3.client('bedrock')

try:
    logging = bedrock.get_model_invocation_logging_configuration()['loggingConfig']

    s3_enabled = logging.get('s3Config', {}).get('bucketName') is not None
    cw_enabled = logging.get('cloudWatchConfig', {}).get('logGroupName') is not None
    text_enabled = logging.get('textDataDeliveryEnabled', False)
    image_enabled = logging.get('imageDataDeliveryEnabled', False)
    embedding_enabled = logging.get('embeddingDataDeliveryEnabled', False)

    print('Model Invocation Logging:\n')

    if not s3_enabled and not cw_enabled:
        print('  STATUS: NOT CONFIGURED')
        print('  WARNING: No invocation logging — no audit trail for model calls')
        print('  Recommendation: Enable logging to S3 or CloudWatch for compliance and debugging')
    else:
        if s3_enabled:
            bucket = logging['s3Config']['bucketName']
            prefix = logging['s3Config'].get('keyPrefix', '')
            print(f'  S3: s3://{bucket}/{prefix}')
        if cw_enabled:
            log_group = logging['cloudWatchConfig']['logGroupName']
            print(f'  CloudWatch: {log_group}')

        print(f'  Text data delivery: {\"enabled\" if text_enabled else \"disabled\"}')
        print(f'  Image data delivery: {\"enabled\" if image_enabled else \"disabled\"}')
        print(f'  Embedding data delivery: {\"enabled\" if embedding_enabled else \"disabled\"}')

except Exception as e:
    print(f'Error checking logging config: {e}')
    print('Note: Requires bedrock:GetModelInvocationLoggingConfiguration permission')
"
```

#### 6b. Bedrock CloudWatch Metrics — Invocation Patterns

```bash
python3 -c "
import boto3, datetime

cw = boto3.client('cloudwatch')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=7)

metrics_to_check = [
    ('Invocations', 'Sum'),
    ('InvocationLatency', 'Average'),
    ('InvocationClientErrors', 'Sum'),
    ('InvocationServerErrors', 'Sum'),
    ('InvocationThrottles', 'Sum'),
    ('InputTokenCount', 'Sum'),
    ('OutputTokenCount', 'Sum'),
]

print('Bedrock Metrics (last 7 days):\n')

for metric_name, stat in metrics_to_check:
    result = cw.get_metric_statistics(
        Namespace='AWS/Bedrock',
        MetricName=metric_name,
        StartTime=start, EndTime=end,
        Period=86400 * 7,
        Statistics=[stat]
    )

    if result['Datapoints']:
        value = result['Datapoints'][0][stat]
        if metric_name == 'InvocationLatency':
            print(f'  {metric_name}: {value:,.0f}ms (avg)')
        elif 'Token' in metric_name:
            print(f'  {metric_name}: {value:,.0f} tokens')
        else:
            print(f'  {metric_name}: {value:,.0f}')
    else:
        print(f'  {metric_name}: no data')

print()
print('Note: For per-model breakdown, filter by ModelId dimension')
"
```

#### 6c. Per-Model Invocation Breakdown

```bash
python3 -c "
import boto3, datetime

cw = boto3.client('cloudwatch')
bedrock = boto3.client('bedrock')
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(days=7)

# Get model IDs from available models
models = bedrock.list_foundation_models()['modelSummaries']

print(f'{'Model':<45} {'Invocations':<15} {'Input Tokens':<15} {'Output Tokens':<15}')
print('-' * 90)

active_models = 0
for m in models:
    model_id = m['modelId']

    invocations = cw.get_metric_statistics(
        Namespace='AWS/Bedrock',
        MetricName='Invocations',
        Dimensions=[{'Name': 'ModelId', 'Value': model_id}],
        StartTime=start, EndTime=end,
        Period=86400 * 7,
        Statistics=['Sum']
    )

    if invocations['Datapoints']:
        inv_count = invocations['Datapoints'][0]['Sum']

        input_tokens = cw.get_metric_statistics(
            Namespace='AWS/Bedrock',
            MetricName='InputTokenCount',
            Dimensions=[{'Name': 'ModelId', 'Value': model_id}],
            StartTime=start, EndTime=end,
            Period=86400 * 7,
            Statistics=['Sum']
        )

        output_tokens = cw.get_metric_statistics(
            Namespace='AWS/Bedrock',
            MetricName='OutputTokenCount',
            Dimensions=[{'Name': 'ModelId', 'Value': model_id}],
            StartTime=start, EndTime=end,
            Period=86400 * 7,
            Statistics=['Sum']
        )

        in_tok = input_tokens['Datapoints'][0]['Sum'] if input_tokens['Datapoints'] else 0
        out_tok = output_tokens['Datapoints'][0]['Sum'] if output_tokens['Datapoints'] else 0

        print(f'{model_id:<45} {inv_count:<15,.0f} {in_tok:<15,.0f} {out_tok:<15,.0f}')
        active_models += 1

if active_models == 0:
    print('No model invocations found in the last 7 days.')
else:
    print(f'\n{active_models} models with activity in the last 7 days')
"
```

### 7. Cost Analysis (Bedrock-Specific)

#### 7a. Bedrock Cost Breakdown

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=USAGE_TYPE \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
  --output json
```

Parse results to show cost by usage type (on-demand inference, provisioned throughput, custom model training, knowledge base storage, etc.).

#### 7b. Bedrock Cost Trend

```bash
aws ce get-cost-and-usage \
  --time-period Start=YYYY-MM-DD,End=YYYY-MM-DD \
  --granularity DAILY \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
  --output json
```

Use daily granularity to detect cost spikes from unexpected invocation surges.

## Domain Knowledge

### Bedrock Service Names in Cost Explorer

Use Workflow 7 with these exact service names:

| Common Name | Cost Explorer Service Name |
|---|---|
| Bedrock | Amazon Bedrock |

Usage types typically include:
- `InvokeModel` — on-demand inference
- `ProvisionedThroughput` — committed capacity
- `CustomModel` — fine-tuning / custom model training
- `KnowledgeBase` — knowledge base storage and queries

### Provisioned Throughput Waste Detection

Provisioned throughput has committed pricing (1-month or 6-month). Zero invocations on active provisioned throughput = direct waste. Unlike on-demand, you pay whether you use it or not.

Priority check: any `InService` provisioned throughput with zero `Invocations` in CloudWatch over 7+ days should be flagged immediately.

### Guardrail Best Practices

A production Bedrock deployment should have at minimum:
1. **Content filtering** — block harmful content generation
2. **PII detection** — prevent leaking sensitive data in responses
3. **Topic restrictions** — deny off-topic or dangerous topics

Missing guardrails = security and compliance risk, not just a best practice gap.

### Logging Gap = Compliance Risk

If `get_model_invocation_logging_configuration` returns no S3 or CloudWatch config, there is no audit trail for:
- What prompts were sent to models
- What responses were generated
- Who invoked which model and when

This is a compliance gap for regulated industries (HIPAA, SOC2, GDPR).

### Permissions Required

- `bedrock:ListFoundationModels`, `bedrock:GetFoundationModel` — model inventory
- `bedrock:ListProvisionedModelThroughputs`, `bedrock:GetProvisionedModelThroughput` — throughput analysis
- `bedrock:ListGuardrails`, `bedrock:GetGuardrail` — guardrail review
- `bedrock:GetModelInvocationLoggingConfiguration` — logging audit
- `bedrock:ListCustomModels`, `bedrock:GetCustomModel` — custom model inventory
- `bedrock-agent:ListKnowledgeBases`, `bedrock-agent:GetKnowledgeBase` — knowledge bases
- `bedrock-agent:ListAgents`, `bedrock-agent:GetAgent` — agents
- `bedrock-agent:ListDataSources` — data source inventory
- `cloudwatch:GetMetricStatistics` — utilization metrics
- `ce:GetCostAndUsage` — cost analysis

The `ReadOnlyAccess` managed policy covers most of these.

### Cross-Reference with Other Skills

- **Cost drill-down** → Use `aws-cost-analyser` to compare Bedrock spend against other services and track trends over time
- **IAM for Bedrock** → Use `aws-iam-analyser` to audit who has `bedrock:InvokeModel`, `bedrock:CreateModelCustomizationJob`, or `bedrock:CreateGuardrail` permissions
- **Resource lifecycle** → Use `aws-resource-analyser` to check if resources connected to knowledge bases (S3 buckets, OpenSearch clusters) are properly tagged and maintained

## Output Formatting

- Present findings as **markdown tables** sorted by impact
- Use severity indicators: `CRITICAL` (no logging, no guardrails in production), `HIGH` (unused provisioned throughput, overly broad model access), `MEDIUM` (missing PII filters, stale knowledge bases), `LOW` (informational)
- Group findings by category (security, waste, configuration, inventory)
- For token usage, show human-readable numbers: `1.2M tokens` not `1234567`
- For costs, format as `$1,234.56` with 2 decimal places
- Always include **actionable recommendations**
- Summary at the end: "Found X critical, Y high, Z medium findings"
