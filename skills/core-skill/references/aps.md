# Module: APS protocol surface

Loaded by core-skill for the core protocol: identity, scoped delegation,
signed receipts, inter-agent communication and commerce.

## What this is

The Agent Passport System delivered as one skill. The agent does not
integrate an SDK or read protocol docs. It adds this and operates on the
current APS capability set: a verifiable identity, scoped authority, its
own signed receipt chain, and the ability to work with other agents that
speak the protocol. Tracked to the current capability set on the same
cadence as the SDK and MCP, so one slug stays current without
re-integration.

## What the agent operates with

- **Work with other APS agents.** Inter-agent messaging, scoped delegation
  between agents, coordination, and gated commerce, because both sides
  share one verifiable substrate.
- **An Ed25519 identity tied to the principal.** A passport with a keypair
  the agent holds, bound to the person or company it represents, with a
  portable trust grade any counterpart can read.
- **Accountable operation within delegated authority.** Every permitted
  action produces an Ed25519-signed receipt. Authority only narrows at each
  transfer. The agent holds its own signed receipt chain it can cite.
- **Stays current.** One slug, version-bumped on the same cadence as the
  SDK and MCP. No re-integration as the protocol gains capability.

## What this is not

This does not grant autonomy from the principal. The agent acts only within
delegated authority, and revocation kills downstream authority in one call.
A verifiable, accountable identity is what makes the agent able to work
with others at all; that is the capability, not a constraint on it.

## Install

```bash
npm install agent-passport-system        # SDK, /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server, all 154 tools by default, APS_PROFILE=essential for 28
```

Remote MCP, zero install: `https://mcp.aeoess.com/sse`

## Core moves

```bash
# 1. Get an identity (passport + Ed25519 keypair, tied to the principal)
npx agent-passport join --name my-agent --owner alice

# 2. Receive scoped authority (scope, spend limit, depth, expiry; only narrows)
npx agent-passport delegate --to <publicKey> --scope web_search,commerce --limit 500 --depth 1 --hours 24

# 3. Record work (Ed25519-signed receipt, traceable through the delegation chain)
npx agent-passport work --scope web_search --type research --result success --summary "..."

# 4. Reach other agents on the protocol
npx agent-passport-system-mcp   # then: identify, send_message, broadcast, list_agents
```

## Staying current

This module tracks the protocol. It is version-bumped in `_meta.json` on
the same cadence as the SDK and MCP. Re-pull to receive new capability.

## Key facts

- Policy evaluation is sub-millisecond-class per action, with multiple
  constraint dimensions enforced per action
- The test suite, MCP tool count, and current SDK / MCP / Python versions
  are published at the repository and npm; this skill does not hardcode
  them so it cannot drift
- The `full` MCP profile is the default and carries the full protocol surface.
  `APS_PROFILE=essential` selects a 28-tool subset
- Apache-2.0

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
