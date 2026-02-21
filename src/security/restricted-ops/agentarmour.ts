// src/security/restricted-ops/agentarmour.ts
import os from "node:os";
import path from "node:path";
import { loadPolicy, type RestrictedOpsPolicy, type PolicyEvaluationResult } from "./policy.js";

/**
 * AgentArmor-lite (no extra LLM):
 * - DFA: per session track whether any untrusted data/observation has been seen in current turn
 * - Provenance registry: mark data origin + turn number + allow $ref resolution
 * - Policy (MVP): HIGH-RISK ops are forbidden if:
 *   (a) tainted==true (after any untrusted observation in current turn), OR
 *   (b) args contain $ref to data not created in current user turn (cross-turn), OR
 *   (c) args contain $ref to non-user-origin data when forbidNonUserData==true
 */

export type OriginKind =
  | "user_prompt"
  | "tool_observation"
  | "file_content"
  | "model_literal"
  | "unknown";

export type DataNode = {
  id: string;
  kind: OriginKind;
  toolName?: string;
  resource?: string; // e.g., file:/abs/path
  turn: number;
  createdAt: number;
  value?: unknown; // stored limited size for resolving $ref
};

export type ProvenancePolicy = {
  enabled: boolean;

  currentTurnOnly: boolean;
  forbidNonUserData: boolean;
  requireCleanForHighRisk: boolean;

  onViolation: "deny" | "confirm";

  highRiskTools: string[];
  trustedObservationTools: string[];

  fileWriteTools: string[];
  fileReadTools: string[];

  maxStoredValueBytes: number;

  /**
   * If you haven't wired beginUserTurn() yet, we infer a new turn when idle time exceeds this.
   */
  turnIdleMs: number;
};

type PendingWrite = {
  toolCallId: string;
  paths: string[];
  turn: number;
  createdAt: number;
};

type SessionState = {
  turn: number;
  tainted: boolean;

  lastEventAt: number; // NEW: for auto-turn inference

  data: Map<string, DataNode>;
  resourceLastWriteTurn: Map<string, number>;
  pendingWrites: Map<string, PendingWrite>;
};

const sessions = new Map<string, SessionState>();

function getSession(sessionId: string): SessionState {
  let s = sessions.get(sessionId);
  if (!s) {
    s = {
      turn: 0,
      tainted: false,
      lastEventAt: 0,
      data: new Map(),
      resourceLastWriteTurn: new Map(),
      pendingWrites: new Map(),
    };
    sessions.set(sessionId, s);
  }
  return s;
}

function now(): number {
  return Date.now();
}

function normalizeAbs(p: string): string {
  const home = os.homedir();
  const expanded = p === "~" ? home : p.startsWith("~/") ? path.join(home, p.slice(2)) : p;
  const abs = path.isAbsolute(expanded)
    ? path.normalize(expanded)
    : path.resolve(process.cwd(), expanded);
  return abs.replace(/\\/g, "/");
}

function safeSizeBytes(v: unknown): number {
  try {
    const s = typeof v === "string" ? v : JSON.stringify(v);
    return Buffer.byteLength(s ?? "", "utf8");
  } catch {
    return 0;
  }
}

function defaultProvenancePolicy(policy: RestrictedOpsPolicy): ProvenancePolicy {
  const p: any = (policy as any).provenance;
  return {
    enabled: p?.enabled ?? true,
    currentTurnOnly: p?.currentTurnOnly ?? true,
    forbidNonUserData: p?.forbidNonUserData ?? true,
    requireCleanForHighRisk: p?.requireCleanForHighRisk ?? true,
    onViolation: p?.onViolation ?? "deny",
    highRiskTools: p?.highRiskTools ?? ["exec", "message", "send_email", "transfer_money"],
    trustedObservationTools: p?.trustedObservationTools ?? [],
    fileWriteTools: p?.fileWriteTools ?? [
      "write_file",
      "apply_patch",
      "append_file",
      "save_to_file",
    ],
    fileReadTools: p?.fileReadTools ?? ["read_file", "load_file"],
    maxStoredValueBytes: p?.maxStoredValueBytes ?? 32_000,
    turnIdleMs: typeof p?.turnIdleMs === "number" && p.turnIdleMs > 0 ? p.turnIdleMs : 15_000,
  };
}

function makeDataId(prefix: string, turn: number, suffix: string): string {
  return `${prefix}:t${turn}:${suffix}`;
}

function isHighRisk(toolName: string, cfg: ProvenancePolicy): boolean {
  if (cfg.highRiskTools.includes(toolName)) return true;
  if (toolName === "exec") return true;
  return false;
}

function maybeAutoBeginTurn(sessionId: string, cfg: ProvenancePolicy, userText?: string): void {
  const s = getSession(sessionId);
  const t = now();

  const shouldStart = s.turn === 0 || (s.lastEventAt > 0 && t - s.lastEventAt > cfg.turnIdleMs);

  if (!shouldStart) {
    s.lastEventAt = t;
    return;
  }

  s.turn += 1;
  s.tainted = false;

  const id = makeDataId("user", s.turn, "prompt");
  if (!s.data.has(id)) {
    const node: DataNode = {
      id,
      kind: "user_prompt",
      turn: s.turn,
      createdAt: t,
      value: userText ?? "", // placeholder if unknown
    };
    s.data.set(id, node);
  }

  s.lastEventAt = t;
}

function collectRefIds(params: unknown): string[] {
  const out: string[] = [];
  const visit = (x: unknown) => {
    if (!x) return;
    if (Array.isArray(x)) {
      for (const i of x) visit(i);
      return;
    }
    if (typeof x === "object") {
      const o = x as Record<string, unknown>;
      if (typeof o.$ref === "string") out.push(o.$ref);
      if (typeof o.ref === "string") out.push(o.ref);
      for (const v of Object.values(o)) visit(v);
    }
  };
  visit(params);
  return Array.from(new Set(out));
}

/**
 * Resolve $ref recursively using registry values.
 * If missing ref -> throws (fail-closed).
 */
export function resolveRefs(sessionId: string, params: unknown): unknown {
  const s = getSession(sessionId);

  const visit = (x: unknown): unknown => {
    if (!x) return x;
    if (Array.isArray(x)) return x.map(visit);

    if (typeof x === "object") {
      const o = x as Record<string, unknown>;
      const ref = typeof o.$ref === "string" ? o.$ref : typeof o.ref === "string" ? o.ref : null;

      if (ref) {
        const node = s.data.get(ref);
        if (!node) throw new Error(`agentarmor: unresolved ref: ${ref}`);
        return node.value;
      }

      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(o)) out[k] = visit(v);
      return out;
    }

    return x;
  };

  return visit(params);
}

/**
 * Start a new "user operation" turn (epoch).
 * Call this when a new user prompt arrives (recommended, more accurate than idle inference).
 */
export function beginUserTurn(
  sessionId: string,
  userText: string,
  policy?: RestrictedOpsPolicy,
): string {
  const resolved = policy ?? loadPolicy();
  const cfg = defaultProvenancePolicy(resolved);
  const s = getSession(sessionId);

  if (!cfg.enabled) return "";

  s.turn += 1;
  s.tainted = false;
  s.lastEventAt = now();

  const id = makeDataId("user", s.turn, "prompt");
  const node: DataNode = {
    id,
    kind: "user_prompt",
    turn: s.turn,
    createdAt: s.lastEventAt,
    value: userText,
  };
  s.data.set(id, node);
  return id;
}

/**
 * Preflight: check a proposed tool call against DFA + provenance rules.
 * Call this BEFORE executing the tool.
 */
export function preflightToolCall(args: {
  sessionId: string;
  toolName: string;
  params: unknown;
  toolCallId?: string;
  policy?: RestrictedOpsPolicy;
}): PolicyEvaluationResult {
  const resolved = args.policy ?? loadPolicy();
  const cfg = defaultProvenancePolicy(resolved);
  if (!cfg.enabled) return { decision: "allow" };

  // Ensure we have a current turn (auto infer if beginUserTurn not wired)
  maybeAutoBeginTurn(args.sessionId, cfg);

  const s = getSession(args.sessionId);
  const highRisk = isHighRisk(args.toolName, cfg);

  // Record pending writes (commit on postToolResult ok)
  if (cfg.fileWriteTools.includes(args.toolName)) {
    const paths = extractFilePathsFromKnownShapes(args.params);
    if (paths.length > 0) {
      const toolCallId = args.toolCallId ?? makeDataId("tc", s.turn, `${args.toolName}_${now()}`);
      s.pendingWrites.set(toolCallId, {
        toolCallId,
        paths: paths.map(normalizeAbs),
        turn: s.turn,
        createdAt: now(),
      });
    }
  }

  const refIds = collectRefIds(args.params);
  const missing: string[] = [];
  const stale: DataNode[] = [];
  const nonUser: DataNode[] = [];

  for (const rid of refIds) {
    const node = s.data.get(rid);
    if (!node) {
      missing.push(rid);
      continue;
    }
    if (cfg.currentTurnOnly && node.turn !== s.turn) stale.push(node);
    if (cfg.forbidNonUserData && node.kind !== "user_prompt") nonUser.push(node);
  }

  if (missing.length > 0) {
    return {
      decision: cfg.onViolation,
      reason: `Unresolved $ref in tool params (fail-closed): ${missing[0]}`,
      ruleId: "prov.ref_unresolved",
      metadata: { toolName: args.toolName, missing },
    };
  }

  if (highRisk) {
    if (cfg.requireCleanForHighRisk && s.tainted) {
      return {
        decision: cfg.onViolation,
        reason: `High-risk tool denied after untrusted observation in this turn: ${args.toolName}`,
        ruleId: "prov.high_risk_after_untrusted",
        metadata: { toolName: args.toolName, turn: s.turn },
      };
    }

    if (stale.length > 0) {
      return {
        decision: cfg.onViolation,
        reason: `High-risk tool denied due to stale data source (not current user operation): ${args.toolName}`,
        ruleId: "prov.high_risk_stale_source",
        metadata: {
          toolName: args.toolName,
          currentTurn: s.turn,
          staleRefs: stale.map((n) => ({
            id: n.id,
            kind: n.kind,
            turn: n.turn,
            tool: n.toolName,
            resource: n.resource,
          })),
        },
      };
    }

    if (nonUser.length > 0) {
      return {
        decision: cfg.onViolation,
        reason: `High-risk tool denied due to non-user data dependency in args: ${args.toolName}`,
        ruleId: "prov.high_risk_non_user_source",
        metadata: {
          toolName: args.toolName,
          nonUserRefs: nonUser.map((n) => ({
            id: n.id,
            kind: n.kind,
            turn: n.turn,
            tool: n.toolName,
            resource: n.resource,
          })),
        },
      };
    }
  }

  return { decision: "allow" };
}

/**
 * Post-hook: record tool observation, update DFA tainting, and commit file writes.
 * Call this AFTER the tool has executed.
 */
export function postToolResult(args: {
  sessionId: string;
  toolName: string;
  result: unknown;
  toolCallId?: string;
  ok?: boolean;
  policy?: RestrictedOpsPolicy;
}): string {
  const resolved = args.policy ?? loadPolicy();
  const cfg = defaultProvenancePolicy(resolved);
  if (!cfg.enabled) return "";

  // Ensure we have a current turn (auto infer)
  maybeAutoBeginTurn(args.sessionId, cfg);

  const s = getSession(args.sessionId);

  // taint unless tool is explicitly trusted
  if (!cfg.trustedObservationTools.includes(args.toolName)) {
    s.tainted = true;
  }

  // commit pending file writes if ok
  const tcid = args.toolCallId;
  if (tcid && s.pendingWrites.has(tcid)) {
    const pending = s.pendingWrites.get(tcid)!;
    if (args.ok !== false) {
      for (const fp of pending.paths) {
        s.resourceLastWriteTurn.set(`file:${fp}`, pending.turn);
      }
    }
    s.pendingWrites.delete(tcid);
  }

  // register observation data node
  const obsId = makeDataId("obs", s.turn, `${args.toolName}_${tcid ?? now()}`);
  const node: DataNode = {
    id: obsId,
    kind: "tool_observation",
    toolName: args.toolName,
    turn: s.turn,
    createdAt: now(),
  };

  // store limited value for resolving refs
  const size = safeSizeBytes(args.result);
  if (size > 0 && size <= cfg.maxStoredValueBytes) node.value = args.result;

  s.data.set(obsId, node);
  s.lastEventAt = now();
  return obsId;
}

/**
 * Optional: allow other subsystems to register file reads as "file_content".
 */
export function registerFileContent(args: {
  sessionId: string;
  filePath: string;
  content: unknown;
  policy?: RestrictedOpsPolicy;
}): string {
  const resolved = args.policy ?? loadPolicy();
  const cfg = defaultProvenancePolicy(resolved);
  if (!cfg.enabled) return "";

  maybeAutoBeginTurn(args.sessionId, cfg);

  const s = getSession(args.sessionId);
  const abs = normalizeAbs(args.filePath);
  const resource = `file:${abs}`;
  const lastTurn = s.resourceLastWriteTurn.get(resource);

  if (cfg.currentTurnOnly && lastTurn && lastTurn !== s.turn) {
    s.tainted = true;
  }
  if (!lastTurn) {
    s.tainted = true;
  }

  const id = makeDataId("file", s.turn, `${path.basename(abs)}_${now()}`);
  const node: DataNode = {
    id,
    kind: "file_content",
    resource,
    turn: lastTurn ?? 0,
    createdAt: now(),
  };

  const size = safeSizeBytes(args.content);
  if (size > 0 && size <= cfg.maxStoredValueBytes) node.value = args.content;

  s.data.set(id, node);
  s.lastEventAt = now();
  return id;
}

/**
 * Debug helper.
 */
export function debugSession(sessionId: string): Record<string, unknown> {
  const s = getSession(sessionId);
  return {
    turn: s.turn,
    tainted: s.tainted,
    lastEventAt: s.lastEventAt,
    dataCount: s.data.size,
    resourceLastWrite: Array.from(s.resourceLastWriteTurn.entries()).slice(0, 50),
    pendingWrites: Array.from(s.pendingWrites.keys()),
  };
}

function extractFilePathsFromKnownShapes(params: unknown): string[] {
  if (!params || typeof params !== "object") return [];
  const p = params as Record<string, unknown>;

  const candidates: string[] = [];
  if (typeof p.path === "string") candidates.push(p.path);
  if (typeof p.filePath === "string") candidates.push(p.filePath);
  if (typeof p.filename === "string") candidates.push(p.filename);
  if (typeof p.target === "string") candidates.push(p.target);

  if (typeof p.dst === "string") candidates.push(p.dst);
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
  return candidates;
}

export function ensureTurn(
  sessionId: string,
  _turnKey?: string,
  policy?: RestrictedOpsPolicy,
): void {
  const resolved = policy ?? loadPolicy();
  const cfg = defaultProvenancePolicy(resolved);
  if (!cfg.enabled) return;

  // Initialize / bump lastEventAt and possibly start a new inferred turn.
  maybeAutoBeginTurn(sessionId, cfg);
}

/**
 * Record a tool result from hooks (after-tool-call).
 * This is a compatibility wrapper used by agentarmour-hooks.ts.
 */
export function recordToolResult(
  sessionId: string,
  _turnKey: string | undefined,
  toolName: string,
  toolCallId: string,
  ok: boolean,
  result: unknown,
  policy?: RestrictedOpsPolicy,
): string {
  return postToolResult({
    sessionId,
    toolName,
    result,
    toolCallId,
    ok,
    policy,
  });
}
