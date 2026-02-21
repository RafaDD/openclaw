// src/agents/pi-tools.after-tool-call.ts
import { createSubsystemLogger } from "../logging/subsystem.js";
import { agentArmorAfterToolFromHook } from "../security/restricted-ops/agentarmour_hook.js";

const log = createSubsystemLogger("agents/pi-tools.after-tool-call");

export default async function afterToolCall(args: unknown): Promise<void> {
  try {
    const a = (args ?? {}) as any;

    const toolName = String(a.toolName ?? a.tool ?? a.name ?? "");
    const toolCallId = String(a.toolCallId ?? a.id ?? a.callId ?? "");
    const ok = a.ok === undefined ? !a.error : Boolean(a.ok);
    const result = a.result ?? a.output ?? a.response ?? a.observation ?? a.data ?? null;
    if (process.env.OPENCLAW_AGENTARMOR_RECORD_FROM_HOOK === "1") {
      await agentArmorAfterToolFromHook({
        args,
        toolName,
        toolCallId,
        ok,
        result,
      });
    } else {
      log.debug(
        `after-tool-call observed (not recorded): tool=${toolName} id=${toolCallId} ok=${ok}`,
      );
    }
  } catch (err) {
    log.warn(`after-tool-call hook error (ignored): ${String(err)}`);
  }
}
