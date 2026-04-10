# AWS Agent Skills

A collection of AWS-focused agent skills for AI coding assistants. Each skill is a `SKILL.md` file that provides deep AWS domain expertise, workflows, and command patterns — teaching your AI agent how to work with AWS services effectively.

Compatible with [Claude Code](https://claude.ai/code), [Cursor](https://cursor.sh), and any AI coding agent that supports the [Agent Skills](https://github.com/anthropics/skills) format.

**Prerequisites**: AWS CLI configured with valid credentials (`aws configure` or `AWS_PROFILE`).

## Skills Catalog

| Skill | Description |
|-------|-------------|
| [aws-cost-analyser](skills/aws-cost-analyser/) | Analyze AWS costs in depth — service breakdown, EC2-Other drill-down, tag-based allocation, multi-account costs, usage type analysis, and cost trends |
| [aws-resource-analyser](skills/aws-resource-analyser/) | Detect unused/idle resources, check tagging compliance, audit security posture, identify right-sizing opportunities, and track resource lifecycle |
| [aws-iam-analyser](skills/aws-iam-analyser/) | Deep IAM security analysis — overly permissive policies, unused roles, cross-account trust, privilege escalation paths, SCPs, permission boundaries, Identity Center audit |

## Installation

### Claude Code (Plugin)

```bash
# Add the marketplace
/plugin marketplace add muralidkt/aws-agent-skills

# Install all AWS skills
/plugin install aws-agent-skills@aws-agent-skills
```

### Claude Code (Manual)

**Global** (available in all projects):

```bash
git clone https://github.com/muralidkt/aws-agent-skills.git /tmp/aws-agent-skills
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser ~/.claude/skills/aws-cost-analyser
```

**Project-level** (available only in a specific project):

```bash
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser .claude/skills/aws-cost-analyser
```

### Cursor

```bash
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser .cursor/skills/aws-cost-analyser
```

### Universal (`.agents/` convention)

```bash
cp -r /tmp/aws-agent-skills/skills/aws-cost-analyser .agents/skills/aws-cost-analyser
```

## Creating a New Skill

1. Copy the template:

```bash
cp -r template/SKILL.md skills/your-skill-name/SKILL.md
```

2. Edit the frontmatter:

```yaml
---
name: your-skill-name
description: >
  What the skill does and when it should activate.
  Include trigger phrases for agent recognition.
---
```

3. Write the skill content with:
   - **When to Activate** — trigger conditions
   - **Prerequisites** — required tools or access
   - **Workflows** — step-by-step command patterns
   - **Domain Knowledge** — gotchas, mappings, best practices
   - **Output Formatting** — how to present results

See [template/SKILL.md](template/SKILL.md) for the full starter template.

## License

Apache 2.0 — see [LICENSE](LICENSE).
