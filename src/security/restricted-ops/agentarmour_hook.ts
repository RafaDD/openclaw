// src/security/restricted-ops/agentarmour_hooks.ts
import type { RestrictedOpsPolicy } from "./policy.js";
import { recordToolResult, ensureTurn } from "./agentarmour.js";
import { loadPolicy } from "./policy.js";

export function deriveSessionAndTurnKey(args: unknown): { sessionId: string; turnKey?: string } {
  const a = (args ?? {}) as any;

  const sessionId =
    a.sessionId ??
    a.session_id ??
    a.conversationId ??
    a.conversation_id ??
    a.threadId ??
    a.thread_id ??
    a.session?.id ??
    a.context?.sessionId ??
    a.context?.conversationId ??
    "default";

  const turnKey =
    a.turnId ??
    a.turn_id ??
    a.runId ??
    a.run_id ??
    a.traceId ??
    a.trace_id ??
    a.requestId ??
    a.request_id ??
    a.messageId ??
    a.message_id ??
    a.rootMessageId ??
    a.root_message_id ??
    a.context?.turnId ??
    a.context?.runId ??
    undefined;

  return { sessionId: String(sessionId), turnKey: turnKey ? String(turnKey) : undefined };
}

/**
 * Call this in before-tool-call to ensure turn is initialized (optional but recommended).
 */
export function agentArmorBeforeToolFromHook(args: unknown): {
  sessionId: string;
  turnKey?: string;
  policy: RestrictedOpsPolicy;
} {
  const policy = loadPolicy();
  const { sessionId, turnKey } = deriveSessionAndTurnKey(args);
  ensureTurn(sessionId, turnKey, policy);
  return { sessionId, turnKey, policy };
}

/**
 * Call this in after-tool-call to record tool outputs (this is what enables multi-step DFA).
 */
export function agentArmorAfterToolFromHook(input: {
  args: unknown;
  toolName: string;
  toolCallId: string;
  ok: boolean;
  result: unknown;
}): void {
  const policy = loadPolicy();
  const { sessionId, turnKey } = deriveSessionAndTurnKey(input.args);
  recordToolResult(
    sessionId,
    turnKey,
    input.toolName,
    input.toolCallId,
    input.ok,
    input.result,
    policy,
  );
}
