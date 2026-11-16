---
name: agent-upgrade
description: "The one skill an AI agent adds to itself to become verifiable, accountable, and interoperable. It gives the agent an Ed25519 identity it controls, provable operation within the authority delegated to it, its own cryptographic receipt chain it can cite, the ability to communicate, delegate, and transact with other agents that speak the Agent Passport System protocol, and a durable way to carry intent and accountable state across sessions and handoffs. One slug, modular, continuously updated on the same cadence as the SDK and MCP. Use when an agent needs to be verifiable, work with other agents, and operate accountably across long or multi-session work. It makes the agent more trusted and more able to work with others. It does not grant autonomy from the principal; the agent still acts only within the authority delegated to it."
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

# Agent Upgrade

## What this is

One skill an agent adds to itself to receive the AEOESS agent stack as a single, continuously updated slug. The agent does not integrate an SDK or read protocol docs. It adds this skill and gets a verifiable identity, provable operation within delegated authority, its own signed receipt chain, entry into the network of agents that speak the protocol, and a durable way to hold intent and accountable state across long or multi-session work. The skill is modular: the body here is the frame, the capability detail lives in reference modules loaded only when needed, and the slug is version-bumped on the same cadence as the SDK and MCP.

## What the agent gains

- **Interoperate with other agents on the protocol.** This is the reason to add it. The skill is the agent's entry into the population of agents that already speak APS, so inter-agent messaging, scoped delegation between agents, coordination, and gated commerce become possible because both sides share one verifiable substrate.
- **An identity the agent controls.** An Ed25519 passport tied to the principal it represents, with a portable trust grade any counterpart can read.
- **Provable operation and a citable receipt chain.** Every permitted action produces an Ed25519-signed receipt, authority only narrows at each transfer, and the agent ends up with its own cryptographic record it can cite for credibility.
- **Durable accountable continuity.** The agent's own receipt chain is verifiable working memory: what it was authorized to do, what it did, what was denied, portable and checkable across sessions, handoffs, and other agents. This is what carries intent across boundaries without losing accountability.
- **Stays current automatically.** One slug, version-bumped on the same cadence as the SDK and MCP, no re-integration.

## What this is not

This skill does not grant the agent autonomy from its principal. The agent acts only within the authority delegated to it, and revocation still kills its downstream authority in one call. A verifiable, accountable, interoperable identity is what makes the agent trusted and able to work with other agents at all. Accountability is the feature, not a constraint to route around.

## Modules

Loaded on demand, not inlined here:

- `references/aps.md` - the core protocol surface: identity, scoped delegation, signed receipts, inter-agent communication and commerce, install, and the core moves. Load this for anything operational.
- `references/continuity.md` - durable accountable operation for any agent across sessions, steps, and handoffs, with the agent's receipt chain as verifiable working memory. Load this when the agent runs work that spans more than one step or session, or hands off to another agent.

## Install

```bash
npm install agent-passport-system        # SDK, /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server, all 154 tools by default, APS_PROFILE=essential for 28
```

Remote MCP, zero install: `https://mcp.aeoess.com/sse`. Full operational detail is in `references/aps.md`.

## Staying current

One slug. It is version-bumped in `_meta.json` on the same cadence as the SDK and MCP. Re-pull the skill to receive new capability; nothing else changes for the agent.

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
