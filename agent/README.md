# Agent Playbooks

This directory contains maintenance guidance for evolving `jumpcloud-mcp` while preserving core guarantees:
- Full JumpCloud API coverage via OpenAPI-driven tools
- Secrets persisted in Vault
- Configuration persisted in Postgres
- Multi-user token model
- Admin-key guard for mutating MCP tools
- Support for external Vault and Postgres services

Contents:
- `agent/playbooks/service-onboarding.md`: checklist for adding new JumpCloud tool domains or capability bundles.
- `agent/templates/service-spec.md`: input template for proposing tool/domain extensions.