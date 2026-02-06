import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import {
  enforcePolicyDecision,
  evaluateDestructiveCommand,
  evaluateNetworkSend,
  evaluatePathOperation,
  evaluateSecretDetection,
  loadPolicy,
} from "./policy.js";

const log = createSubsystemLogger("security/restricted-ops");

export type ToolCallContext = {
  toolName: string;
  params: unknown;
  toolCallId?: string;
};

export type PathOperationContext = {
  filePath: string;
  operation: "add" | "modify" | "delete" | "move";
};

export type ExecCommandContext = {
  command: string;
  argv: string[];
};

export type NetworkSendContext = {
  channel: string;
  recipient: string;
};

/**
 * Single integration point for restricted operations policy.
 * Call this before executing any tool to enforce all policy rules.
 */
export async function checkToolCall(context: ToolCallContext): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  try {
    const policy = loadPolicy();
    const secretEval = await evaluateSecretDetection(context.toolName, context.params, policy);
    const enforcement = await enforcePolicyDecision(secretEval, context.toolName);
    if (!enforcement.allowed) {
      return enforcement;
    }
    return { allowed: true };
  } catch (err) {
    log.warn(
      `restricted-ops policy check failed: tool=${context.toolName} error=${String(err)}`,
    );
    return { allowed: true }; // Fail open on errors
  }
}

/**
 * Check if a file operation is allowed by policy.
 */
export async function checkPathOperation(context: PathOperationContext): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  try {
    const pathEval = await evaluatePathOperation(context.filePath, context.operation);
    const enforcement = await enforcePolicyDecision(pathEval, "apply_patch");
    return enforcement;
  } catch (err) {
    log.warn(
      `restricted-ops path check failed: path=${context.filePath} error=${String(err)}`,
    );
    return { allowed: true }; // Fail open on errors
  }
}

/**
 * Check if a shell command is allowed by policy.
 */
export async function checkExecCommand(context: ExecCommandContext): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  try {
    const destructiveEval = await evaluateDestructiveCommand(context.command, context.argv);
    const enforcement = await enforcePolicyDecision(destructiveEval, "exec");
    return enforcement;
  } catch (err) {
    log.warn(
      `restricted-ops exec check failed: command=${context.command} error=${String(err)}`,
    );
    return { allowed: true }; // Fail open on errors
  }
}

/**
 * Check if a network send is allowed by policy.
 */
export async function checkNetworkSend(context: NetworkSendContext): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  try {
    const networkEval = await evaluateNetworkSend(context.channel, context.recipient);
    const enforcement = await enforcePolicyDecision(networkEval, "message");
    return enforcement;
  } catch (err) {
    log.warn(
      `restricted-ops network check failed: channel=${context.channel} error=${String(err)}`,
    );
    return { allowed: true }; // Fail open on errors
  }
}

