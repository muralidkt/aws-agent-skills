# Real-World Example: Combining aws-cost-analyser + aws-resource-analyser to Cut Your AWS Bill

This example walks through a real-world cost optimisation scenario using two skills from this repo together: **aws-cost-analyser** and **aws-resource-analyser**. It's the kind of investigation that used to take a cloud engineer half a day — now it's a conversation with your AI agent.

---

## The Scenario

You're a platform engineer at a mid-size SaaS company. Your AWS bill jumped from $4,200 to $6,800 in a single month — a $2,600 spike with no obvious cause. You have a production EKS cluster, a handful of RDS instances, several EC2 workloads, and an S3 data lake.

Your manager wants answers by EOD.

---

## Step 1: Find Where the Money Went (aws-cost-analyser)

Start with the cost analyser skill. Ask your agent:

> "Break down my AWS costs for last month vs the month before, by service"

The skill runs Cost Explorer and returns something like:

```
Service             Apr        Mar        Delta
--------------------------------------------------
EC2-Instances       $1,840     $1,790     +$50
EC2-Other           $2,310     $680       +$1,630  ⚠️
RDS                 $890       $870       +$20
S3                  $420       $390       +$30
EKS                 $340       $310       +$30
Data Transfer       $890       $160       +$730   ⚠️
```

Two big spikes: **EC2-Other** (+$1,630) and **Data Transfer** (+$730). Combined, that's $2,360 of your $2,600 overage.

EC2-Other is notoriously opaque. Ask the agent to drill in:

> "Drill into EC2-Other — what usage types are driving the cost?"

```
Usage Type                          Apr       Mar       Delta
--------------------------------------------------------------
NatGateway-Bytes                    $1,180    $210      +$970  🚨
NatGateway-Hours                    $290      $280      +$10
LoadBalancerUsage                   $420      $120      +$300  ⚠️
VpcEndpoint-Hours                   $210      $45       +$165  ⚠️
```

NAT Gateway data processing: **$970 spike in a single month.**

---

## Step 2: Find the Waste (aws-resource-analyser)

Now you know *what* is costing money. Use the resource analyser to find *why* and *what you can clean up.*

> "Find unused or oversized resources — EC2, NAT Gateways, load balancers"

The skill scans across regions and returns:

```
IDLE EC2 INSTANCES (CPU < 5% for 14+ days)
  i-0a3f8b2c1d4e5f6a  t3.xlarge  eu-west-1  prod-batch-worker  $142/mo
  i-0b7e9d1a2c3f4g5h  t3.large   eu-west-1  staging-api-old    $73/mo

UNDERUTILISED NAT GATEWAYS
  nat-0c1d2e3f4a5b6c7d  eu-west-1a  6.2 GB/day → $186/mo processed data
  nat-0d2e3f4a5b6c7d8e  eu-west-1b  0.1 GB/day → $31/mo  (idle standby?)

UNUSED LOAD BALANCERS (0 healthy targets)
  arn:...:loadbalancer/app/staging-api-alb   eu-west-1  $22/mo
  arn:...:loadbalancer/app/old-internal-alb  eu-west-1  $18/mo

UNATTACHED EBS VOLUMES (30+ days)
  vol-0e3f4a5b6c7d8e9f  500 GB gp2  eu-west-1a  $50/mo
  vol-0f4a5b6c7d8e9f0a  200 GB gp2  eu-west-1a  $20/mo

VPC ENDPOINTS (low traffic)
  vpce-0a1b2c3d4e5f  com.amazonaws.eu-west-1.s3  $165/mo  (0.2 GB/hr avg)
```

---

## Step 3: Connect the Dots

Now ask the agent to connect the cost spike with the resource findings:

> "The NAT Gateway data spike was $970. Can you cross-reference which resources are routing traffic through the NAT Gateways in eu-west-1?"

The skill checks VPC Flow Logs (if enabled) and routing tables:

```
NAT Gateway traffic sources (eu-west-1a, last 30 days):
  10.0.12.45  →  i-0a3f8b2c1d4e5f6a  (prod-batch-worker)  → 4.8 TB processed
  10.0.14.22  →  EKS node group       → 1.2 TB processed
  10.0.15.10  →  i-0b7e9d1a2c3f4g5h  (staging-api-old)    → 0.8 TB processed
```

**Root cause found:** `prod-batch-worker` — that idle t3.xlarge with <5% CPU — processed **4.8 TB through the NAT Gateway** last month. It's a batch job pulling data from an external API and writing to S3, but it's routing via NAT instead of a VPC endpoint for S3.

The fix is two lines:
1. Add a VPC Endpoint for S3 (free for Gateway endpoints, eliminates NAT data processing charges for S3 traffic)
2. Review whether the batch job actually needs to be t3.xlarge or can be a Lambda/Fargate task

---

## Step 4: Quantify the Savings

Ask the agent to summarise the actionable findings with estimated savings:

```
QUICK WINS (implement this week)
  Remove unused ALBs (staging-api-alb, old-internal-alb)     → Save $40/mo
  Delete unattached EBS volumes (700 GB gp2)                 → Save $70/mo
  Terminate staging-api-old EC2 (confirmed unused)           → Save $73/mo
  --------------------------------------------------------
  Total quick wins:                                           $183/mo

MEDIUM EFFORT (1-2 days work)
  Add S3 VPC Gateway Endpoint → eliminate NAT Gateway        → Save ~$900/mo
  batch-worker traffic
  Right-size prod-batch-worker to t3.medium (or Fargate)     → Save $100/mo
  --------------------------------------------------------
  Total medium effort:                                        ~$1,000/mo

REVIEW REQUIRED
  VPC Interface Endpoints ($165/mo) — evaluate if direct     TBD
  S3 access justifies the cost vs Gateway endpoint
  EKS NAT traffic (1.2 TB) — audit pod egress patterns       TBD
  --------------------------------------------------------

ESTIMATED TOTAL SAVINGS:                                      ~$1,183/mo
```

You've found the cause of the spike, have a clear remediation plan, and can recover most of the overage — in a single conversation.

---

## Why Two Skills Together

Neither skill alone tells the full story:

- **Cost analyser alone** tells you NAT Gateway costs spiked. It doesn't tell you which EC2 instance is causing it.
- **Resource analyser alone** tells you an EC2 instance has low CPU. It doesn't connect that to the NAT Gateway spend.

Together, they let you trace **from billing line item → resource → root cause → fix**.

---

## Installing Both Skills

```bash
git clone https://github.com/muralidkt/aws-agent-skills.git /tmp/aws-agent-skills

# Claude Code (global)
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser ~/.claude/skills/
cp -r /tmp/aws-agent-skills/skills/aws-resource-analyser ~/.claude/skills/

# Or project-level
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser .claude/skills/
cp -r /tmp/aws-agent-skills/skills/aws-resource-analyser .claude/skills/
```

Then in Claude Code:

```
> Analyse my AWS costs for last month and find any idle or unused resources
```

The agent picks up both skills and runs the combined workflow automatically.

---

## More Skills

→ [aws-iam-analyser](skills/aws-iam-analyser/) — audit IAM for overly permissive policies, unused roles, privilege escalation paths

More skills coming: `aws-security-analyser`, `aws-bedrock-analyser`, `aws-eks-analyser`

Contributions welcome — see the [template](template/) to add your own.
