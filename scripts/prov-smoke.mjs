import { beginUserTurn, postToolResult, preflightToolCall } from "../dist/security/restricted-ops/agentarmour.js";

function pickObsId(ret) {
  if (!ret) return "";
  if (typeof ret === "string") return ret;
  // 兼容多种可能返回形态
  return ret.obsId ?? ret.id ?? ret.ref ?? "";
}

function show(title, r) {
  console.log("\n===", title, "===");
  console.log(JSON.stringify(r, null, 2));
}

const S = "prov-smoke-session";

// CASE 0: 干净情况下，高风险（exec）应当 allow（如果你的 policy 默认是 allow）
beginUserTurn(S, "hello");
const r0 = preflightToolCall({
  sessionId: S,
  toolName: "exec",
  params: { command: "echo hi" },
});
show("CASE0 clean exec", r0);

// CASE 1: 本 turn 产生一个 tool observation（默认非 trusted），然后高风险应当被拦（taint 总闸）
beginUserTurn(S, "turn1");
const ret1 = postToolResult({
  sessionId: S,
  toolName: "read",
  ok: true,
  toolCallId: "t1",
  result: { content: "SECRET_FROM_TOOL" },
});
const obs1 = pickObsId(ret1);
show("CASE1 postToolResult return", { ret1, obs1 });

const r1 = preflightToolCall({
  sessionId: S,
  toolName: "exec",
  params: { command: "echo should_block" },
});
show("CASE1 taint blocks high risk", r1);

// CASE 2: 用 $ref 引用 tool observation —— 走 provenance 分支（如果你的 policy 配置为 forbidNonUserData/currentTurnOnly）
beginUserTurn(S, "turn2");
const ret2 = postToolResult({
  sessionId: S,
  toolName: "read",
  ok: true,
  toolCallId: "t2",
  result: { content: "TOOL_OUTPUT_2" },
});
const obs2 = pickObsId(ret2);

const r2 = preflightToolCall({
  sessionId: S,
  toolName: "exec",
  params: { command: { $ref: obs2 } },
});
show("CASE2 $ref non-user source blocks", { obs2, r2 });

// CASE 3: 跨 turn 引用旧 $ref（currentTurnOnly=true 时应当拦）
beginUserTurn(S, "turn3");
const r3 = preflightToolCall({
  sessionId: S,
  toolName: "exec",
  params: { command: { $ref: obs2 } },
});
show("CASE3 stale $ref blocks", { obs2, r3 });

// CASE 4: $ref 不存在（应当 fail-closed）
beginUserTurn(S, "turn4");
const r4 = preflightToolCall({
  sessionId: S,
  toolName: "exec",
  params: { command: { $ref: "obs:t999:missing" } },
});
show("CASE4 missing $ref blocks", r4);

console.log("\nDONE.");
