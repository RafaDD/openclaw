# Restricted Operations Policy

A centralized policy enforcement system that protects OpenClaw from dangerous operations by blocking or requiring confirmation for restricted actions.

## Overview

This module enforces four core security rules:

1. **System-critical paths**: Blocks file operations on system directories (`/usr`, `/etc`, `/Windows`, etc.)
2. **User-space destructive operations**: Requires confirmation for deletes/moves in personal folders (`~/Documents`, `~/Desktop`)
3. **Network sends**: Blocks outbound messages unless recipient/domain is in allowlist
4. **Secret detection**: Requires confirmation when high-entropy strings (API keys, tokens) are detected in tool parameters

## Architecture

### Files

- **`policy.ts`**: Core policy engine with evaluation functions and policy loading
- **`integration.ts`**: Simple integration API with one function per check type
- **`index.ts`**: Main export point (import from here)
- **`policy.test.ts`**: Unit tests

### Design Principles

1. **Fail-safe**: Policy errors log warnings but don't crash the system (fail open)
2. **Centralized**: All policy logic lives in this folder
3. **Simple API**: Each integration point uses a single function call
4. **Human confirmation**: Uses existing exec approvals socket for confirmations

## Usage

### Integration Points

The policy is automatically enforced at four choke points:

1. **Tool calls** (`src/agents/pi-tools.before-tool-call.ts`)
   ```typescript
   import { checkToolCall } from "../security/restricted-ops/index.js";
   const check = await checkToolCall({ toolName, params, toolCallId });
   ```

2. **File operations** (`src/agents/apply-patch.ts`)
   ```typescript
   import { checkPathOperation } from "../security/restricted-ops/index.js";
   const check = await checkPathOperation({ filePath, operation: "delete" });
   ```

3. **Shell commands** (`src/agents/bash-tools.exec.ts`)
   ```typescript
   import { checkExecCommand } from "../security/restricted-ops/index.js";
   const check = await checkExecCommand({ command, argv });
   ```

4. **Network sends** (`src/infra/outbound/message-action-runner.ts`)
   ```typescript
   import { checkNetworkSend } from "../security/restricted-ops/index.js";
   const check = await checkNetworkSend({ channel, recipient });
   ```

### Policy File

Policy configuration lives at `~/.openclaw/policy.json`:

```json
{
  "version": 1,
  "enabled": true,
  "restrictedPaths": {
    "systemCritical": ["/usr", "/etc", "/Windows"]
  },
  "userSpace": {
    "confirmOnDestructive": ["Documents", "Desktop"]
  },
  "network": {
    "allowlist": {
      "slack": ["#general", "#dev"],
      "email": ["@example.com"]
    }
  },
  "secrets": {
    "enabled": true,
    "minLength": 20,
    "entropyThreshold": 3.5,
    "exceptions": {
      "tools": [],
      "fields": ["buffer", "base64", "media"]
    }
  }
}
```

**Quick Disable**: Set `"enabled": false` to disable all policy checks:

```json
{
  "version": 1,
  "enabled": false
}
```

When disabled, all operations are allowed without any policy checks.

## Decision Flow

Each check returns one of three decisions:

- **`allow`**: Operation permitted
- **`deny`**: Operation blocked immediately
- **`confirm`**: Requires human approval via exec approvals socket

The `enforcePolicyDecision()` function handles confirmations automatically, requesting approval and blocking if denied.

## Adding New Rules

1. Add evaluation function in `policy.ts` (e.g., `evaluateNewRule()`)
2. Add integration function in `integration.ts` (e.g., `checkNewRule()`)
3. Export from `index.ts`
4. Call from appropriate integration point

## Testing

Run tests with:
```bash
pnpm test src/security/restricted-ops/policy.test.ts
```

Tests cover path restrictions, secret detection, network allowlists, and destructive command classification.

