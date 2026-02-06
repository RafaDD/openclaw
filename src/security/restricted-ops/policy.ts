import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { requestExecApprovalViaSocket, resolveExecApprovals } from "../../infra/exec-approvals.js";

export type PolicyDecision = "allow" | "deny" | "confirm";

export type PolicyEvaluationResult = {
  decision: PolicyDecision;
  reason?: string;
  ruleId?: string;
  metadata?: Record<string, unknown>;
};

export type RestrictedOpsPolicy = {
  version: 1;
  enabled?: boolean;
  restrictedPaths?: {
    systemCritical?: string[];
  };
  userSpace?: {
    confirmOnDestructive?: string[];
  };
  network?: {
    allowlist?: Record<string, string[]>;
  };
  secrets?: {
    enabled?: boolean;
    minLength?: number;
    entropyThreshold?: number;
    exceptions?: {
      tools?: string[];
      fields?: string[];
    };
  };
};

const DEFAULT_POLICY: RestrictedOpsPolicy = {
  version: 1,
  enabled: true,
  restrictedPaths: {
    systemCritical: [
      "/Windows",
      "/System",
      "/usr",
      "/etc",
      "/mnt/c/Windows",
      "/mnt/c/System",
      "/Program Files",
      "/Program Files (x86)",
      "/mnt/c/Program Files",
      "/mnt/c/Program Files (x86)",
    ],
  },
  userSpace: {
    confirmOnDestructive: ["Documents", "Desktop", "Downloads"],
  },
  network: {
    allowlist: {},
  },
  secrets: {
    enabled: true,
    minLength: 20,
    entropyThreshold: 3.5,
    exceptions: {
      tools: [],
      fields: ["buffer", "base64", "media", "mediaUrl", "mediaUrls"],
    },
  },
};

const DEFAULT_POLICY_PATH = "~/.openclaw/policy.json";

function expandHome(value: string): string {
  if (!value) {
    return value;
  }
  if (value === "~") {
    return os.homedir();
  }
  if (value.startsWith("~/")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

export function resolvePolicyPath(): string {
  return expandHome(DEFAULT_POLICY_PATH);
}

function normalizePolicy(file: Partial<RestrictedOpsPolicy>): RestrictedOpsPolicy {
  const version = file.version === 1 ? 1 : 1;
  return {
    version,
    enabled:
      typeof file.enabled === "boolean" ? file.enabled : DEFAULT_POLICY.enabled ?? true,
    restrictedPaths: {
      systemCritical: Array.isArray(file.restrictedPaths?.systemCritical)
        ? file.restrictedPaths.systemCritical
        : DEFAULT_POLICY.restrictedPaths?.systemCritical ?? [],
    },
    userSpace: {
      confirmOnDestructive: Array.isArray(file.userSpace?.confirmOnDestructive)
        ? file.userSpace.confirmOnDestructive
        : DEFAULT_POLICY.userSpace?.confirmOnDestructive ?? [],
    },
    network: {
      allowlist:
        file.network?.allowlist && typeof file.network.allowlist === "object"
          ? file.network.allowlist
          : DEFAULT_POLICY.network?.allowlist ?? {},
    },
    secrets: {
      enabled:
        typeof file.secrets?.enabled === "boolean"
          ? file.secrets.enabled
          : DEFAULT_POLICY.secrets?.enabled ?? true,
      minLength:
        typeof file.secrets?.minLength === "number" && file.secrets.minLength > 0
          ? file.secrets.minLength
          : DEFAULT_POLICY.secrets?.minLength ?? 20,
      entropyThreshold:
        typeof file.secrets?.entropyThreshold === "number" && file.secrets.entropyThreshold > 0
          ? file.secrets.entropyThreshold
          : DEFAULT_POLICY.secrets?.entropyThreshold ?? 3.5,
      exceptions: {
        tools: Array.isArray(file.secrets?.exceptions?.tools)
          ? file.secrets.exceptions.tools
          : DEFAULT_POLICY.secrets?.exceptions?.tools ?? [],
        fields: Array.isArray(file.secrets?.exceptions?.fields)
          ? file.secrets.exceptions.fields
          : DEFAULT_POLICY.secrets?.exceptions?.fields ?? [],
      },
    },
  };
}

let cachedPolicy: RestrictedOpsPolicy | null = null;
let cachedPolicyPath: string | null = null;

export function loadPolicy(): RestrictedOpsPolicy {
  const filePath = resolvePolicyPath();
  if (cachedPolicy && cachedPolicyPath === filePath && fs.existsSync(filePath)) {
    return cachedPolicy;
  }
  try {
    if (!fs.existsSync(filePath)) {
      cachedPolicy = DEFAULT_POLICY;
      cachedPolicyPath = filePath;
      return cachedPolicy;
    }
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<RestrictedOpsPolicy>;
    cachedPolicy = normalizePolicy(parsed);
    cachedPolicyPath = filePath;
    return cachedPolicy;
  } catch {
    cachedPolicy = DEFAULT_POLICY;
    cachedPolicyPath = filePath;
    return cachedPolicy;
  }
}

export function clearPolicyCache(): void {
  cachedPolicy = null;
  cachedPolicyPath = null;
}

function normalizePath(filePath: string): string {
  const expanded = expandHome(filePath);
  const resolved = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(expanded);
  return process.platform === "win32" ? resolved.replace(/\\/g, "/") : resolved;
}

function isSystemCriticalPath(filePath: string, policy: RestrictedOpsPolicy): boolean {
  const normalized = normalizePath(filePath);
  const prefixes = policy.restrictedPaths?.systemCritical ?? [];
  for (const prefix of prefixes) {
    const normalizedPrefix = normalizePath(prefix);
    if (normalized === normalizedPrefix || normalized.startsWith(`${normalizedPrefix}/`)) {
      return true;
    }
  }
  return false;
}

function isUserSpacePath(filePath: string, policy: RestrictedOpsPolicy): boolean {
  const normalized = normalizePath(filePath);
  const home = os.homedir();
  if (!normalized.startsWith(home)) {
    return false;
  }
  const relative = path.relative(home, normalized);
  if (!relative || relative.startsWith("..")) {
    return false;
  }
  const folders = policy.userSpace?.confirmOnDestructive ?? [];
  for (const folder of folders) {
    const folderPath = path.join(home, folder);
    if (normalized === folderPath || normalized.startsWith(`${folderPath}/`)) {
      return true;
    }
  }
  return false;
}

function calculateEntropy(str: string): number {
  if (str.length === 0) {
    return 0;
  }
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikeSecret(
  value: unknown,
  toolName: string,
  fieldName: string,
  policy: RestrictedOpsPolicy,
): boolean {
  if (!policy.secrets?.enabled) {
    return false;
  }
  const exceptions = policy.secrets.exceptions;
  if (exceptions?.tools?.includes(toolName)) {
    return false;
  }
  if (exceptions?.fields?.includes(fieldName)) {
    return false;
  }
  if (typeof value !== "string") {
    return false;
  }
  const trimmed = value.trim();
  const minLength = policy.secrets?.minLength ?? 20;
  if (trimmed.length < minLength) {
    return false;
  }
  const entropy = calculateEntropy(trimmed);
  const threshold = policy.secrets?.entropyThreshold ?? 3.5;
  if (entropy < threshold) {
    return false;
  }
  const commonPatterns = [
    /^[A-Za-z0-9_-]{20,}$/,
    /^sk-[A-Za-z0-9_-]{20,}$/,
    /^pk_[A-Za-z0-9_-]{20,}$/,
    /^[A-Za-z0-9]{32,}$/,
    /^[A-Za-z0-9+/=]{40,}$/,
    /^Bearer\s+[A-Za-z0-9._-]+$/,
    /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/,
  ];
  for (const pattern of commonPatterns) {
    if (pattern.test(trimmed)) {
      return true;
    }
  }
  return entropy >= threshold;
}

function scanParamsForSecrets(
  params: unknown,
  toolName: string,
  policy: RestrictedOpsPolicy,
  path = "",
): Array<{ field: string; value: string }> {
  const secrets: Array<{ field: string; value: string }> = [];
  if (typeof params === "string") {
    const fieldName = path || "value";
    if (looksLikeSecret(params, toolName, fieldName, policy)) {
      secrets.push({ field: fieldName, value: params });
    }
  } else if (Array.isArray(params)) {
    for (let i = 0; i < params.length; i += 1) {
      const item = params[i];
      const itemPath = path ? `${path}[${i}]` : `[${i}]`;
      secrets.push(...scanParamsForSecrets(item, toolName, policy, itemPath));
    }
  } else if (params && typeof params === "object") {
    for (const [key, value] of Object.entries(params)) {
      const fieldPath = path ? `${path}.${key}` : key;
      secrets.push(...scanParamsForSecrets(value, toolName, policy, fieldPath));
    }
  }
  return secrets;
}

export async function evaluatePathOperation(
  filePath: string,
  operation: "add" | "modify" | "delete" | "move",
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) {
    return { decision: "allow" };
  }
  const normalized = normalizePath(filePath);
  if (isSystemCriticalPath(normalized, resolvedPolicy)) {
    return {
      decision: "deny",
      reason: `Operation on system-critical path blocked: ${filePath}`,
      ruleId: "system-critical-path",
      metadata: { path: normalized, operation },
    };
  }
  const isDestructive = operation === "delete" || operation === "move";
  if (isDestructive && isUserSpacePath(normalized, resolvedPolicy)) {
    return {
      decision: "confirm",
      reason: `Destructive operation on user-space path requires confirmation: ${filePath}`,
      ruleId: "user-space-destructive",
      metadata: { path: normalized, operation },
    };
  }
  return { decision: "allow" };
}

export async function evaluateSecretDetection(
  toolName: string,
  params: unknown,
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) {
    return { decision: "allow" };
  }
  const secrets = scanParamsForSecrets(params, toolName, resolvedPolicy);
  if (secrets.length > 0) {
    return {
      decision: "confirm",
      reason: `High-entropy string detected in tool parameters (possible secret): ${secrets[0].field}`,
      ruleId: "secret-detection",
      metadata: {
        toolName,
        detectedFields: secrets.map((s) => s.field),
        count: secrets.length,
      },
    };
  }
  return { decision: "allow" };
}

export async function evaluateNetworkSend(
  channel: string,
  recipient: string,
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) {
    return { decision: "allow" };
  }
  const allowlist = resolvedPolicy.network?.allowlist ?? {};
  const channelAllowlist = allowlist[channel] ?? [];
  if (channelAllowlist.length === 0) {
    return {
      decision: "deny",
      reason: `No allowlist configured for channel: ${channel}`,
      ruleId: "network-allowlist-missing",
      metadata: { channel, recipient },
    };
  }
  let matched = false;
  for (const pattern of channelAllowlist) {
    if (pattern === recipient || recipient.includes(pattern) || pattern.includes(recipient)) {
      matched = true;
      break;
    }
    try {
      const url = new URL(recipient);
      const domain = url.hostname;
      if (domain === pattern || domain.endsWith(`.${pattern}`) || pattern.endsWith(`.${domain}`)) {
        matched = true;
        break;
      }
    } catch {
      if (recipient.toLowerCase().includes(pattern.toLowerCase())) {
        matched = true;
        break;
      }
    }
  }
  if (!matched) {
    return {
      decision: "deny",
      reason: `Recipient/domain not in allowlist for channel ${channel}: ${recipient}`,
      ruleId: "network-allowlist-mismatch",
      metadata: { channel, recipient, allowlist: channelAllowlist },
    };
  }
  return { decision: "allow" };
}

export async function evaluateDestructiveCommand(
  command: string,
  argv: string[],
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) {
    return { decision: "allow" };
  }
  const destructiveCommands = new Set([
    "rm",
    "rmdir",
    "del",
    "rd",
    "format",
    "mkfs",
    "dd",
    "shred",
    "wipe",
    "sdelete",
  ]);
  const firstToken = argv[0]?.toLowerCase() ?? command.toLowerCase().split(/\s+/)[0];
  if (destructiveCommands.has(firstToken)) {
    const cwd = process.cwd();
    const home = os.homedir();
    for (let i = 1; i < argv.length; i += 1) {
      const arg = argv[i];
      if (!arg || arg.startsWith("-")) {
        continue;
      }
      try {
        const resolved = path.isAbsolute(arg) ? path.normalize(arg) : path.resolve(cwd, arg);
        if (isUserSpacePath(resolved, resolvedPolicy)) {
          return {
            decision: "confirm",
            reason: `Destructive command targeting user-space path requires confirmation: ${command}`,
            ruleId: "user-space-destructive-command",
            metadata: { command, target: resolved },
          };
        }
      } catch {
        continue;
      }
    }
  }
  return { decision: "allow" };
}

export type PolicyApprovalRequest = {
  type: "policy.request";
  ruleId: string;
  toolName?: string;
  reason: string;
  metadata?: Record<string, unknown>;
};

export async function requestPolicyApproval(
  request: PolicyApprovalRequest,
): Promise<"allow-once" | "allow-always" | "deny" | null> {
  const approvals = resolveExecApprovals();
  if (!approvals.socketPath || !approvals.token) {
    return null;
  }
  return await requestExecApprovalViaSocket({
    socketPath: approvals.socketPath,
    token: approvals.token,
    request: {
      type: "policy.request",
      ruleId: request.ruleId,
      toolName: request.toolName,
      reason: request.reason,
      metadata: request.metadata,
    },
    timeoutMs: 30_000,
  });
}

export async function enforcePolicyDecision(
  evaluation: PolicyEvaluationResult,
  toolName?: string,
): Promise<{ allowed: boolean; reason?: string }> {
  if (evaluation.decision === "allow") {
    return { allowed: true };
  }
  if (evaluation.decision === "deny") {
    return { allowed: false, reason: evaluation.reason };
  }
  if (evaluation.decision === "confirm") {
    const approval = await requestPolicyApproval({
      type: "policy.request",
      ruleId: evaluation.ruleId ?? "unknown",
      toolName,
      reason: evaluation.reason ?? "Policy requires confirmation",
      metadata: evaluation.metadata,
    });
    if (approval === "allow-once" || approval === "allow-always") {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: evaluation.reason ?? "Policy confirmation denied",
    };
  }
  return { allowed: false, reason: "Unknown policy decision" };
}

