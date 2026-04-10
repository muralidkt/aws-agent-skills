# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AWS Agent Skills — a collection of `SKILL.md` files that teach AI coding agents how to work with AWS services. Each skill provides domain expertise, CLI/boto3 command patterns, and workflows for AWS analysis tasks. Compatible with Claude Code, Cursor, and the Agent Skills format.

## Repository Structure

- `skills/<skill-name>/SKILL.md` — Individual skills (the actual content)
- `.claude-plugin/marketplace.json` — Plugin registry for `/plugin install` support
- `template/SKILL.md` — Starter template for new skills

## Skill Authoring Rules

Every `SKILL.md` must include YAML frontmatter with `name` and `description` (include trigger phrases). Required sections: **Safety**, **When to Activate**, **Prerequisites**, **Core Workflows**, **Domain Knowledge**, **Output Formatting**.

All skills in this repo are **read-only** — they must NEVER include commands that create, modify, or delete AWS resources. Only `describe-*`, `list-*`, `get-*` API calls. Remediation is always recommended, never executed.

When adding a new skill:
1. Copy `template/SKILL.md` to `skills/<skill-name>/SKILL.md`
2. Add the skill path to `.claude-plugin/marketplace.json` in the `skills` array
3. Update the Skills Catalog table in `README.md`

## Conventions

- Skill names use lowercase with hyphens: `aws-cost-analyser`
- British spelling for "analyser" (consistent across existing skills)
- CLI commands use `--output json` for parseability; inline `python3 -c` with boto3 for complex logic
- Cross-reference related skills in the Domain Knowledge section
