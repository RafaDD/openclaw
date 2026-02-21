// src/security/restricted-ops/integration.ts
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { preflightToolCall, resolveRefs } from "./agentarmour.js";
import {
  enforcePolicyDecision,
  evaluateDestructiveCommand,
  evaluateNetworkSend,
  evaluatePathAccess,
  evaluatePathOperation,
  evaluateSecretDetection,
  extractPathsFromCommandArgs,
  loadPolicy,
} from "./policy.js";

const log = createSubsystemLogger("security/restricted-ops");

export type ToolCallContext = {
  sessionId?: string; // NEW
  toolName: string;
  params: unknown;
  toolCallId?: string;
};

export type PathOperationContext = {
  filePath: string;
  operation: "add" | "modify" | "delete" | "move";
};

export type ExecCommandContext = {
  sessionId?: string; // NEW (optional)
  command: string;
  argv: string[];
};

export type NetworkSendContext = {
  channel: string;
  recipient: string;
};

/**
 * Best-effort: extract file paths from known tool parameter shapes.
 * Unknown tool => fail-closed deny.
 */
function extractPathsFromToolCall(toolName: string, params: unknown): string[] | null {
  if (!params || typeof params !== "object") return null;
  const p = params as Record<string, unknown>;

  const candidates: unknown[] = [];

  if (typeof p.path === "string") candidates.push(p.path);
  if (typeof p.filePath === "string") candidates.push(p.filePath);
  if (typeof p.filename === "string") candidates.push(p.filename);
  if (typeof p.target === "string") candidates.push(p.target);

  if (typeof p.src === "string") candidates.push(p.src);
  if (typeof p.dst === "string") candidates.push(p.dst);
  if (typeof p.from === "string") candidates.push(p.from);
  if (typeof p.to === "string") candidates.push(p.to);

  const patches = p.patches;
  if (Array.isArray(patches)) {
    for (const item of patches) {
      if (item && typeof item === "object") {
        const o = item as Record<string, unknown>;
        if (typeof o.path === "string") candidates.push(o.path);
        if (typeof o.filePath === "string") candidates.push(o.filePath);
      }
    }
  }

  const out = candidates.filter((x) => typeof x === "string") as string[];
  return out.length > 0 ? out : null;
}

/**
 * Single integration point for restricted operations policy.
 */
export async function checkToolCall(
  context: ToolCallContext,
): Promise<{ allowed: boolean; reason?: string }> {
  const tool = context.toolName;
  const sessionId = context.sessionId ?? "default";

  try {
    const policy = loadPolicy();

    log.info(
      `tool policy input: session=${sessionId} tool=${tool} toolCallId=${context.toolCallId ?? "-"} paramsType=${typeof context.params}`,
    );

    // 0) provenance/DFA preflight (deterministic multi-step)
    const provEval = preflightToolCall({
      sessionId,
      toolName: tool,
      params: context.params,
      toolCallId: context.toolCallId,
      policy,
    });

    const provEnf = await enforcePolicyDecision(provEval, tool);
    if (!provEnf.allowed) {
      log.info(
        `tool policy deny: tool=${tool} rule=${provEval.ruleId ?? "-"} reason=${provEnf.reason ?? "-"}`,
      );
      return provEnf;
    }

    // 1) resolve refs (so secrets/path checks see real values)
    let resolvedParams: unknown = context.params;
    try {
      resolvedParams = resolveRefs(sessionId, context.params);
    } catch (e) {
      const reason = `Failed to resolve $ref in tool params (fail-closed): ${String(e)}`;
      log.info(`tool policy deny: tool=${tool} rule=prov.ref_unresolved reason=${reason}`);
      return { allowed: false, reason };
    }

    // 2) secrets
    const secretEval = await evaluateSecretDetection(tool, resolvedParams, policy);
    const secretEnf = await enforcePolicyDecision(secretEval, tool);
    if (!secretEnf.allowed) {
      log.info(
        `tool policy deny: tool=${tool} rule=${secretEval.ruleId ?? "-"} reason=${secretEnf.reason ?? "-"}`,
      );
      return secretEnf;
    }

    // 3) exec special case
    if (tool === "exec") {
      const p = resolvedParams as any;
      const command = typeof p === "string" ? p : typeof p?.command === "string" ? p.command : "";

      const argv = Array.isArray(p?.argv)
        ? p.argv.map(String)
        : command
          ? command.trim().split(/\s+/)
          : [];

      return await checkExecCommand({ sessionId, command, argv });
    }

    // 4) path access checks (for tools we recognize)
    const paths = extractPathsFromToolCall(tool, resolvedParams);
    if (!paths) {
      const reason = `Tool parameters not recognized for safe path enforcement: ${tool}`;
      log.info(`tool policy deny: tool=${tool} rule=tool.params_unrecognized reason=${reason}`);
      return { allowed: false, reason };
    }

    log.info(`tool policy paths: tool=${tool} paths=${JSON.stringify(paths)}`);

    for (const filePath of paths) {
      const accessEval = await evaluatePathAccess(filePath, policy);
      const accessEnf = await enforcePolicyDecision(accessEval, tool);
      if (!accessEnf.allowed) {
        log.info(
          `tool policy deny: tool=${tool} path=${filePath} rule=${accessEval.ruleId ?? "-"} reason=${accessEnf.reason ?? "-"}`,
        );
        return accessEnf;
      }
    }

    log.info(`tool policy allow: tool=${tool}`);
    return { allowed: true };
  } catch (err) {
    log.warn(`tool policy error (fail-closed): tool=${tool} error=${String(err)}`);
    return { allowed: false, reason: "restricted-ops policy check failed (fail-closed)" };
  }
}

export async function checkPathOperation(
  context: PathOperationContext,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const policy = loadPolicy();
    log.info(`pathop policy input: op=${context.operation} path=${context.filePath}`);

    const pathEval = await evaluatePathOperation(context.filePath, context.operation, policy);
    const enforcement = await enforcePolicyDecision(pathEval, "apply_patch");

    if (!enforcement.allowed) {
      log.info(
        `pathop policy deny: op=${context.operation} path=${context.filePath} rule=${pathEval.ruleId ?? "-"} reason=${enforcement.reason ?? "-"}`,
      );
      return enforcement;
    }

    log.info(`pathop policy allow: op=${context.operation} path=${context.filePath}`);
    return enforcement;
  } catch (err) {
    log.warn(`pathop policy error (fail-closed): path=${context.filePath} error=${String(err)}`);
    return { allowed: false, reason: "restricted-ops path check failed (fail-closed)" };
  }
}

export async function checkExecCommand(
  context: ExecCommandContext,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const policy = loadPolicy();

    log.info(
      `exec policy input: session=${context.sessionId ?? "default"} command="${context.command}" argv=${JSON.stringify(context.argv)}`,
    );

    const eval1 = await evaluateDestructiveCommand(context.command, context.argv, policy);
    const enf1 = await enforcePolicyDecision(eval1, "exec");
    if (!enf1.allowed) {
      log.info(`exec policy deny: rule=${eval1.ruleId ?? "-"} reason=${enf1.reason ?? "-"}`);
      return enf1;
    }

    const paths = extractPathsFromCommandArgs(context.argv);
    if (paths.length > 0) {
      log.info(`exec policy argv paths: ${JSON.stringify(paths)}`);
    }
    for (const p of paths) {
      const accessEval = await evaluatePathAccess(p, policy);
      const accessEnf = await enforcePolicyDecision(accessEval, "exec");
      if (!accessEnf.allowed) {
        log.info(
          `exec policy deny: path=${p} rule=${accessEval.ruleId ?? "-"} reason=${accessEnf.reason ?? "-"}`,
        );
        return accessEnf;
      }
    }

    log.info(`exec policy allow`);
    return { allowed: true };
  } catch (err) {
    log.warn(`exec policy error (fail-closed): command=${context.command} error=${String(err)}`);
    return { allowed: false, reason: "restricted-ops exec check failed (fail-closed)" };
  }
}

export async function checkNetworkSend(
  context: NetworkSendContext,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const policy = loadPolicy();
    log.info(`net policy input: channel=${context.channel} recipient=${context.recipient}`);

    const networkEval = await evaluateNetworkSend(context.channel, context.recipient, policy);
    const enforcement = await enforcePolicyDecision(networkEval, "message");

    if (!enforcement.allowed) {
      log.info(
        `net policy deny: rule=${networkEval.ruleId ?? "-"} reason=${enforcement.reason ?? "-"}`,
      );
      return enforcement;
    }

    log.info(`net policy allow: channel=${context.channel}`);
    return enforcement;
  } catch (err) {
    log.warn(`net policy error (fail-closed): channel=${context.channel} error=${String(err)}`);
    return { allowed: false, reason: "restricted-ops network check failed (fail-closed)" };
  }
}
