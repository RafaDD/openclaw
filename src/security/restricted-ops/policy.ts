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

  /**
   * allow-roots: Any file access MUST be under one of these roots, otherwise deny.
   * If omitted/empty: defaults to workspaceRoot.
   */
  allowedRoots?: string[];

  restrictedPaths?: {
    systemCritical?: string[];
  };

  /**
   * Deny-on-any-access for these folders under $HOME
   */
  userSpace?: {
    denyOnAnyAccess?: string[];
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

  /**
   * NEW: provenance + DFA multi-step enforcement (AgentArmor-lite)
   */
  provenance?: {
    enabled?: boolean;

    /**
     * Enforce "non-current user operation data sources are forbidden"
     * for HIGH-RISK operations.
     */
    currentTurnOnly?: boolean;

    /**
     * Enforce "non-user-origin data dependencies are forbidden" for HIGH-RISK ops.
     * (tool obs, file content, etc.)
     */
    forbidNonUserData?: boolean;

    /**
     * If any untrusted observation happened in this turn, forbid HIGH-RISK ops.
     */
    requireCleanForHighRisk?: boolean;

    /**
     * "deny" or "confirm" (confirm => ask exec-approval socket)
     */
    onViolation?: "deny" | "confirm";

    highRiskTools?: string[];
    trustedObservationTools?: string[];
    fileWriteTools?: string[];
    fileReadTools?: string[];

    maxStoredValueBytes?: number;
  };
};

const DEFAULT_POLICY: RestrictedOpsPolicy = {
  version: 1,
  enabled: true,
  allowedRoots: [],

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

      "~/Downloads",
      "/mnt/c/Users/35517/Downloads",
    ],
  },

  userSpace: {
    denyOnAnyAccess: ["Documents", "Desktop"],
  },

  network: {
    allowlist: {},
  },

  secrets: {
    enabled: false,
    minLength: 20,
    entropyThreshold: 3.5,
    exceptions: {
      tools: [],
      fields: ["buffer", "base64", "media", "mediaUrl", "mediaUrls"],
    },
  },

  provenance: {
    enabled: true,
    currentTurnOnly: true,
    forbidNonUserData: true,
    requireCleanForHighRisk: true,
    onViolation: "deny",
    highRiskTools: ["exec", "message", "send_email", "transfer_money"],
    trustedObservationTools: [],
    // ✅ 补齐你运行时真实 tool 名：read/write（否则 provenance 可能识别不到文件污染）
    fileWriteTools: ["write", "write_file", "apply_patch", "append_file", "save_to_file"],
    fileReadTools: ["read", "read_file", "load_file"],
    maxStoredValueBytes: 32_000,
  },
};

const DEFAULT_POLICY_PATH = "~/.openclaw/policy.json";

function expandHome(value: string): string {
  if (!value) return value;
  if (value === "~") return os.homedir();
  if (value.startsWith("~/")) return path.join(os.homedir(), value.slice(2));
  return value;
}

export function resolvePolicyPath(): string {
  return expandHome(DEFAULT_POLICY_PATH);
}

function normalizePolicy(file: Partial<RestrictedOpsPolicy>): RestrictedOpsPolicy {
  const version = file.version === 1 ? 1 : 1;

  return {
    version,
    enabled: typeof file.enabled === "boolean" ? file.enabled : (DEFAULT_POLICY.enabled ?? true),

    allowedRoots: Array.isArray(file.allowedRoots)
      ? file.allowedRoots
      : (DEFAULT_POLICY.allowedRoots ?? []),

    restrictedPaths: {
      systemCritical: Array.isArray(file.restrictedPaths?.systemCritical)
        ? file.restrictedPaths.systemCritical
        : (DEFAULT_POLICY.restrictedPaths?.systemCritical ?? []),
    },

    userSpace: {
      denyOnAnyAccess: Array.isArray(file.userSpace?.denyOnAnyAccess)
        ? file.userSpace.denyOnAnyAccess
        : (DEFAULT_POLICY.userSpace?.denyOnAnyAccess ?? []),
    },

    network: {
      allowlist:
        file.network?.allowlist && typeof file.network.allowlist === "object"
          ? file.network.allowlist
          : (DEFAULT_POLICY.network?.allowlist ?? {}),
    },

    secrets: {
      enabled:
        typeof file.secrets?.enabled === "boolean"
          ? file.secrets.enabled
          : (DEFAULT_POLICY.secrets?.enabled ?? true),

      minLength:
        typeof file.secrets?.minLength === "number" && file.secrets.minLength > 0
          ? file.secrets.minLength
          : (DEFAULT_POLICY.secrets?.minLength ?? 20),

      entropyThreshold:
        typeof file.secrets?.entropyThreshold === "number" && file.secrets.entropyThreshold > 0
          ? file.secrets.entropyThreshold
          : (DEFAULT_POLICY.secrets?.entropyThreshold ?? 3.5),

      exceptions: {
        tools: Array.isArray(file.secrets?.exceptions?.tools)
          ? file.secrets.exceptions.tools
          : (DEFAULT_POLICY.secrets?.exceptions?.tools ?? []),
        fields: Array.isArray(file.secrets?.exceptions?.fields)
          ? file.secrets.exceptions.fields
          : (DEFAULT_POLICY.secrets?.exceptions?.fields ?? []),
      },
    },

    provenance: {
      enabled:
        typeof file.provenance?.enabled === "boolean"
          ? file.provenance.enabled
          : (DEFAULT_POLICY.provenance?.enabled ?? true),
      currentTurnOnly:
        typeof file.provenance?.currentTurnOnly === "boolean"
          ? file.provenance.currentTurnOnly
          : (DEFAULT_POLICY.provenance?.currentTurnOnly ?? true),
      forbidNonUserData:
        typeof file.provenance?.forbidNonUserData === "boolean"
          ? file.provenance.forbidNonUserData
          : (DEFAULT_POLICY.provenance?.forbidNonUserData ?? true),
      requireCleanForHighRisk:
        typeof file.provenance?.requireCleanForHighRisk === "boolean"
          ? file.provenance.requireCleanForHighRisk
          : (DEFAULT_POLICY.provenance?.requireCleanForHighRisk ?? true),
      onViolation:
        file.provenance?.onViolation === "confirm"
          ? "confirm"
          : (DEFAULT_POLICY.provenance?.onViolation ?? "deny"),
      highRiskTools: Array.isArray(file.provenance?.highRiskTools)
        ? file.provenance!.highRiskTools!
        : (DEFAULT_POLICY.provenance?.highRiskTools ?? []),
      trustedObservationTools: Array.isArray(file.provenance?.trustedObservationTools)
        ? file.provenance!.trustedObservationTools!
        : (DEFAULT_POLICY.provenance?.trustedObservationTools ?? []),
      fileWriteTools: Array.isArray(file.provenance?.fileWriteTools)
        ? file.provenance!.fileWriteTools!
        : (DEFAULT_POLICY.provenance?.fileWriteTools ?? []),
      fileReadTools: Array.isArray(file.provenance?.fileReadTools)
        ? file.provenance!.fileReadTools!
        : (DEFAULT_POLICY.provenance?.fileReadTools ?? []),
      maxStoredValueBytes:
        typeof file.provenance?.maxStoredValueBytes === "number" &&
        file.provenance.maxStoredValueBytes > 0
          ? file.provenance.maxStoredValueBytes
          : (DEFAULT_POLICY.provenance?.maxStoredValueBytes ?? 32_000),
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

/**
 * Workspace root:
 * 1) policy.allowedRoots[0] if provided
 * 2) env OPENCLAW_WORKSPACE_ROOT / WORKSPACE_ROOT / WORKSPACE
 * 3) default ~/.openclaw/workspace   (✅ make it deterministic; avoid PWD drift)
 * 4) process.cwd()
 */
function resolveWorkspaceRoot(policy: RestrictedOpsPolicy): string {
  const fromPolicy = (policy.allowedRoots ?? []).find(
    (x) => typeof x === "string" && x.trim().length > 0,
  );
  if (fromPolicy) return normalizePath(fromPolicy, process.cwd());

  const fromEnv =
    process.env.OPENCLAW_WORKSPACE_ROOT || process.env.WORKSPACE_ROOT || process.env.WORKSPACE;

  if (fromEnv) return normalizePath(fromEnv, process.cwd());

  // ✅ deterministic default without policy.json
  const defaultWs = path.join(os.homedir(), ".openclaw", "workspace");
  if (fs.existsSync(defaultWs)) return normalizePath(defaultWs, process.cwd());

  // last resort
  return normalizePath(process.cwd(), process.cwd());
}

function normalizePath(filePath: string, baseDir: string): string {
  const expanded = expandHome(filePath);
  const resolved = path.isAbsolute(expanded)
    ? path.normalize(expanded)
    : path.resolve(baseDir, expanded);
  return process.platform === "win32" ? resolved.replace(/\\/g, "/") : resolved;
}

/**
 * Realpath defense against symlink escape.
 * - If target exists: realpath(target)
 * - If target doesn't exist: realpath(parent) + basename
 *
 * ✅ FIX: parent may not exist. Must not throw (otherwise integration.ts will fail-closed).
 */
function resolveForPolicyTarget(filePathAbs: string): string {
  const norm = (p: string) => (process.platform === "win32" ? p.replace(/\\/g, "/") : p);

  try {
    return norm(fs.realpathSync(filePathAbs));
  } catch {
    const parent = path.dirname(filePathAbs);

    let base: string;
    try {
      base = fs.realpathSync(parent);
    } catch {
      // parent missing => fallback to normalized parent (no realpath)
      base = parent;
    }

    return norm(path.join(base, path.basename(filePathAbs)));
  }
}

function normalizePrefix(prefix: string, baseDir: string): string {
  return normalizePath(prefix, baseDir);
}

function matchesPrefix(targetAbs: string, prefixAbs: string): boolean {
  return targetAbs === prefixAbs || targetAbs.startsWith(`${prefixAbs}/`);
}

function isUnderAnyAllowedRoot(targetAbs: string, rootsAbs: string[]): boolean {
  for (const r of rootsAbs) {
    if (matchesPrefix(targetAbs, r)) return true;
  }
  return false;
}

function isSystemCriticalPath(
  targetAbs: string,
  policy: RestrictedOpsPolicy,
  baseDir: string,
): boolean {
  const prefixes = policy.restrictedPaths?.systemCritical ?? [];
  for (const prefix of prefixes) {
    const p = normalizePrefix(prefix, baseDir);
    if (matchesPrefix(targetAbs, p)) return true;
  }
  return false;
}

function isUserSpaceSensitivePath(targetAbs: string, policy: RestrictedOpsPolicy): boolean {
  const home = os.homedir();
  const homeNorm = process.platform === "win32" ? home.replace(/\\/g, "/") : home;

  if (!matchesPrefix(targetAbs, homeNorm)) return false;

  const relative = path.posix.relative(homeNorm, targetAbs);
  if (!relative || relative.startsWith("..")) return false;

  const folders = policy.userSpace?.denyOnAnyAccess ?? [];
  for (const folder of folders) {
    const folderPath = path.posix.join(homeNorm, folder);
    if (matchesPrefix(targetAbs, folderPath)) return true;
  }
  return false;
}

/**
 * Central path access decision.
 * Rule order:
 * 1) allow-roots (must be under) => otherwise deny
 * 2) systemCritical prefixes => deny
 * 3) sensitive $HOME folders => deny
 */
export async function evaluatePathAccess(
  filePath: string,
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) return { decision: "allow" };

  const baseDir = resolveWorkspaceRoot(resolvedPolicy);

  // Resolve absolute for policy + symlink hardening
  const abs = normalizePath(filePath, baseDir);
  const targetAbs = resolveForPolicyTarget(abs);

  // Allowed roots
  const rootsRaw = (resolvedPolicy.allowedRoots ?? []).filter(
    (x) => typeof x === "string" && x.trim().length > 0,
  );
  const roots = (rootsRaw.length > 0 ? rootsRaw : [baseDir]).map((r) => {
    const rr = normalizePath(r, baseDir);
    try {
      const rp = fs.realpathSync(rr);
      return process.platform === "win32" ? rp.replace(/\\/g, "/") : rp;
    } catch {
      return rr;
    }
  });

  if (!isUnderAnyAllowedRoot(targetAbs, roots)) {
    return {
      decision: "deny",
      reason: `Access denied (outside allowedRoots): ${filePath}`,
      ruleId: "path.outside_allowed_roots",
      metadata: { path: targetAbs, allowedRoots: roots, baseDir },
    };
  }

  if (isSystemCriticalPath(targetAbs, resolvedPolicy, baseDir)) {
    return {
      decision: "deny",
      reason: `Access denied (blocked prefix): ${filePath}`,
      ruleId: "path.blocked",
      metadata: { path: targetAbs },
    };
  }

  if (isUserSpaceSensitivePath(targetAbs, resolvedPolicy)) {
    return {
      decision: "deny",
      reason: `Access denied (sensitive home folder): ${filePath}`,
      ruleId: "path.home_sensitive",
      metadata: { path: targetAbs },
    };
  }

  return { decision: "allow" };
}

/**
 * Conservative path extraction from argv (non-shell-wrapped only).
 */
export function extractPathsFromCommandArgs(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 1; i < argv.length; i += 1) {
    let arg = argv[i];
    if (!arg) continue;

    if (/^[a-zA-Z]+:\/\//.test(arg)) continue;

    if (arg.startsWith("--") && arg.includes("=")) {
      const value = arg.split("=", 2)[1];
      if (value) arg = value;
    }

    if (arg.startsWith("-")) continue;

    const looksPath =
      arg.startsWith("/") ||
      arg.startsWith("~/") ||
      arg === "~" ||
      arg.includes("/") ||
      arg.includes("\\");
    if (!looksPath) continue;

    out.push(arg);
  }
  return out;
}

function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;

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
  if (!policy.secrets?.enabled) return false;

  const exceptions = policy.secrets.exceptions;
  if (exceptions?.tools?.includes(toolName)) return false;
  if (exceptions?.fields?.includes(fieldName)) return false;

  if (typeof value !== "string") return false;

  const trimmed = value.trim();
  const minLength = policy.secrets?.minLength ?? 20;
  if (trimmed.length < minLength) return false;

  const entropy = calculateEntropy(trimmed);
  const threshold = policy.secrets?.entropyThreshold ?? 3.5;
  if (entropy < threshold) return false;

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
    if (pattern.test(trimmed)) return true;
  }
  return entropy >= threshold;
}

function scanParamsForSecrets(
  params: unknown,
  toolName: string,
  policy: RestrictedOpsPolicy,
  pathName = "",
): Array<{ field: string; value: string }> {
  const secrets: Array<{ field: string; value: string }> = [];

  if (typeof params === "string") {
    const fieldName = pathName || "value";
    if (looksLikeSecret(params, toolName, fieldName, policy))
      secrets.push({ field: fieldName, value: params });
    return secrets;
  }

  if (Array.isArray(params)) {
    for (let i = 0; i < params.length; i += 1) {
      const itemPath = pathName ? `${pathName}[${i}]` : `[${i}]`;
      secrets.push(...scanParamsForSecrets(params[i], toolName, policy, itemPath));
    }
    return secrets;
  }

  if (params && typeof params === "object") {
    for (const [key, value] of Object.entries(params)) {
      const fieldPath = pathName ? `${pathName}.${key}` : key;
      secrets.push(...scanParamsForSecrets(value, toolName, policy, fieldPath));
    }
  }

  return secrets;
}

export async function evaluateSecretDetection(
  toolName: string,
  params: unknown,
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) return { decision: "allow" };

  const secrets = scanParamsForSecrets(params, toolName, resolvedPolicy);
  if (secrets.length > 0) {
    return {
      decision: "deny",
      reason: `High-entropy string detected in tool parameters (possible secret): ${secrets[0].field}`,
      ruleId: "secrets.detected",
      metadata: {
        toolName,
        detectedFields: secrets.map((s) => s.field),
        count: secrets.length,
      },
    };
  }

  return { decision: "allow" };
}

export async function evaluatePathOperation(
  filePath: string,
  operation: "add" | "modify" | "delete" | "move",
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) return { decision: "allow" };

  const access = await evaluatePathAccess(filePath, resolvedPolicy);
  if (access.decision !== "allow") {
    return { ...access, metadata: { ...(access.metadata ?? {}), operation } };
  }
  return { decision: "allow" };
}

export async function evaluateNetworkSend(
  channel: string,
  recipient: string,
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) return { decision: "allow" };

  const allowlist = resolvedPolicy.network?.allowlist ?? {};
  const channelAllowlist = allowlist[channel] ?? [];

  if (channelAllowlist.length === 0) {
    return {
      decision: "deny",
      reason: `No allowlist configured for channel: ${channel}`,
      ruleId: "network.not_allowlisted",
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
      ruleId: "network.not_allowlisted",
      metadata: { channel, recipient, allowlist: channelAllowlist },
    };
  }

  return { decision: "allow" };
}

function isShellWrapped(argv: string[]): boolean {
  const a0 = (argv[0] ? path.basename(argv[0]) : "").toLowerCase();
  const shells = new Set(["bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"]);
  if (!shells.has(a0)) return false;
  return argv.some((x) => x === "-c" || x === "-lc" || x.toLowerCase() === "/c");
}

export async function evaluateDestructiveCommand(
  command: string,
  argv: string[],
  policy?: RestrictedOpsPolicy,
): Promise<PolicyEvaluationResult> {
  const resolvedPolicy = policy ?? loadPolicy();
  if (resolvedPolicy.enabled === false) return { decision: "allow" };

  if (isShellWrapped(argv)) {
    return {
      decision: "deny",
      reason: `Shell-wrapped exec denied (fail-closed): ${command}`,
      ruleId: "exec.shell_wrapped",
      metadata: { command, argv },
    };
  }

  const paths = extractPathsFromCommandArgs(argv);
  for (const p of paths) {
    const access = await evaluatePathAccess(p, resolvedPolicy);
    if (access.decision !== "allow") {
      return {
        decision: "deny",
        reason: `Command argument targets denied path: ${command}`,
        ruleId: access.ruleId ?? "path.denied",
        metadata: { command, argPath: p, ...access.metadata },
      };
    }
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

  const firstToken = (argv[0] ?? "").toLowerCase() || command.toLowerCase().split(/\s+/)[0];
  if (destructiveCommands.has(firstToken)) {
    if (paths.length === 0) {
      return {
        decision: "deny",
        reason: `Destructive command denied (no explicit target paths): ${command}`,
        ruleId: "command.destructive.no_target",
        metadata: { command, argv },
      };
    }
    return { decision: "allow" };
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
  if (!approvals.socketPath || !approvals.token) return null;

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

/**
 * UPDATED: confirm => ask approval socket; if not available => deny.
 */
export async function enforcePolicyDecision(
  evaluation: PolicyEvaluationResult,
  toolName?: string,
): Promise<{ allowed: boolean; reason?: string }> {
  if (evaluation.decision === "allow") return { allowed: true };
  if (evaluation.decision === "deny") return { allowed: false, reason: evaluation.reason };

  // confirm => approval
  const approval = await requestPolicyApproval({
    type: "policy.request",
    ruleId: evaluation.ruleId ?? "policy.confirm",
    toolName,
    reason: evaluation.reason ?? "Policy confirmation required",
    metadata: evaluation.metadata,
  });

  if (approval === "allow-once" || approval === "allow-always") {
    return { allowed: true };
  }
  return { allowed: false, reason: evaluation.reason ?? "Policy denied" };
}
