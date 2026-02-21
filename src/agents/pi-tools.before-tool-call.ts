import type { AnyAgentTool } from "./tools/common.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
// NEW: advance DFA/provenance AFTER tool returns
import { postToolResult } from "../security/restricted-ops/agentarmour.js";
import { checkToolCall } from "../security/restricted-ops/index.js";
import { normalizeToolName } from "./tool-policy.js";

type HookContext = {
  agentId?: string;
  sessionKey?: string;
  // NEW: allow canonical id passthrough if callers prefer sessionId over sessionKey
  sessionId?: string;
};

type HookOutcome = { blocked: true; reason: string } | { blocked: false; params: unknown };

const log = createSubsystemLogger("agents/tools");

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// NEW: stable session id derivation
function deriveSessionId(ctx?: HookContext): string {
  const sk = ctx?.sessionKey;
  if (typeof sk === "string" && sk.trim().length > 0) return sk.trim();

  const sid = ctx?.sessionId;
  if (typeof sid === "string" && sid.trim().length > 0) return sid.trim();

  return "default";
}

// NEW: clone to avoid mutating the stored observation when we decorate the returned result
function cloneForStore<T>(value: T): T {
  // Fast path: primitives + null/undefined
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t !== "object") return value;

  // structuredClone exists in modern Node; fall back to original if it fails
  try {
    // eslint-disable-next-line no-undef
    return structuredClone(value);
  } catch {
    return value;
  }
}

// NEW: expose observation ref to the model (without requiring a second model)
function decorateToolOutput(raw: any, obsId: string | undefined) {
  if (!obsId) return raw;

  // For objects/arrays, attach metadata directly if possible
  if (raw !== null && typeof raw === "object") {
    try {
      (raw as any).__prov_ref = obsId;
      return raw;
    } catch {
      // fall through to wrapper
    }
  }

  // For primitives (string/number/bool), wrap so the model can read __prov_ref
  return { value: raw, __prov_ref: obsId };
}

export async function runBeforeToolCallHook(args: {
  toolName: string;
  params: unknown;
  toolCallId?: string;
  ctx?: HookContext;
}): Promise<HookOutcome> {
  const toolName = normalizeToolName(args.toolName || "tool");
  const params = args.params;

  const sessionId = deriveSessionId(args.ctx);

  // Enforce restricted operations policy (NOW includes DFA/provenance preflight)
  const policyCheck = await checkToolCall({
    sessionId,
    toolName,
    params,
    toolCallId: args.toolCallId,
  });

  if (!policyCheck.allowed) {
    return {
      blocked: true,
      reason: policyCheck.reason ?? "Policy violation",
    };
  }

  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("before_tool_call")) {
    return { blocked: false, params: args.params };
  }

  try {
    const normalizedParams = isPlainObject(params) ? params : {};
    const hookResult = await hookRunner.runBeforeToolCall(
      {
        toolName,
        params: normalizedParams,
      },
      {
        toolName,
        agentId: args.ctx?.agentId,
        sessionKey: args.ctx?.sessionKey,
      },
    );

    if (hookResult?.block) {
      return {
        blocked: true,
        reason: hookResult.blockReason || "Tool call blocked by plugin hook",
      };
    }

    if (hookResult?.params && isPlainObject(hookResult.params)) {
      if (isPlainObject(params)) {
        return { blocked: false, params: { ...params, ...hookResult.params } };
      }
      return { blocked: false, params: hookResult.params };
    }
  } catch (err) {
    const toolCallId = args.toolCallId ? ` toolCallId=${args.toolCallId}` : "";
    log.warn(`before_tool_call hook failed: tool=${toolName}${toolCallId} error=${String(err)}`);
  }

  return { blocked: false, params };
}

export function wrapToolWithBeforeToolCallHook(
  tool: AnyAgentTool,
  ctx?: HookContext,
): AnyAgentTool {
  const execute = tool.execute;
  if (!execute) return tool;

  const toolName = tool.name || "tool";

  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const sessionId = deriveSessionId(ctx);

      const outcome = await runBeforeToolCallHook({
        toolName,
        params,
        toolCallId,
        ctx,
      });

      if (outcome.blocked) {
        // IMPORTANT: do NOT call postToolResult here.
        // This was not a real tool execution, and recording it can taint the session incorrectly.
        throw new Error(outcome.reason);
      }

      try {
        const rawResult = await execute(toolCallId, outcome.params, signal, onUpdate);

        // CRITICAL: advance DFA/provenance AFTER tool completes (success)
        // Store a clone to avoid mutation when we decorate the returned result with __prov_ref.
        let obsId: string | undefined;
        try {
          obsId = postToolResult({
            sessionId,
            toolName: normalizeToolName(toolName),
            result: cloneForStore(rawResult),
            toolCallId,
            ok: true,
          });
        } catch (e) {
          log.warn(
            `postToolResult failed (ignored): tool=${toolName} toolCallId=${toolCallId} error=${String(e)}`,
          );
        }

        return decorateToolOutput(rawResult, obsId);
      } catch (err) {
        // still advance with failure (exactly once)
        try {
          postToolResult({
            sessionId,
            toolName: normalizeToolName(toolName),
            result: { error: String(err) },
            toolCallId,
            ok: false,
          });
        } catch {
          // ignore
        }
        throw err;
      }
    },
  };
}

export const __testing = {
  runBeforeToolCallHook,
  isPlainObject,
  deriveSessionId,
};
