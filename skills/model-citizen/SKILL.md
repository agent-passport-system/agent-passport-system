---
name: model-citizen
description: "Early release. The AEOESS skill for agents that operate accountably: verifiable Ed25519 identity tied to the principal, scoped authority that only narrows, and a signed receipt for every action, built on the Agent Passport System. The agent acts only within delegated authority. Apache-2.0. This is an early release; capability is expanding."
metadata:
  clawdbot:
    emoji: "🛂"
    requires:
      bins: ["npx"]
      env: ["GITHUB_TOKEN (optional, only for register_agora_public)"]
    network:
      - "mcp.aeoess.com (remote MCP server, SSE mode)"
      - "api.aeoess.com (Intent Network API)"
    install:
      - id: node
        kind: node
        package: agent-passport-system
        bins: ["agent-passport"]
        label: "Install Agent Passport System"
---

# model-citizen

Early release. This is the AEOESS skill for agents that operate
accountably, built on the Agent Passport System.

## What this is

An agent that adds this, under its principal's authorization, gets a
verifiable Ed25519 identity tied to the person or company it represents,
scoped authority that only narrows at each transfer, and a signed receipt
for every permitted action. The receipt chain is checkable across
sessions, handoffs, and other agents without trusting the issuer.

## What this is not

This does not expand the agent's authority, autonomy, or ability to act
without approval. Authority is delegated by the principal and revoking it
kills the agent's downstream authority in one call. A verifiable,
accountable identity is what lets the agent be trusted to work with others
at all; that is the capability, not a limit on it.

## Install

```bash
npm install agent-passport-system        # SDK, /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server, all 154 tools by default, APS_PROFILE=essential for 28
```

Remote MCP, zero install: `https://mcp.aeoess.com/sse`

## Core moves

```bash
# Identity (passport + Ed25519 keypair, tied to the principal)
npx agent-passport join --name my-agent --owner alice

# Scoped authority (scope, spend limit, depth, expiry; only narrows)
npx agent-passport delegate --to <publicKey> --scope web_search --limit 500 --depth 1 --hours 24

# Record work (Ed25519-signed receipt, traceable through the chain)
npx agent-passport work --scope web_search --type research --result success --summary "..."
```

## Status

Early release. Capability is expanding on the same cadence as the SDK and
MCP. Re-pull to receive updates.

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
