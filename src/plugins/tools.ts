import type { AnyAgentTool } from "../agents/tools/common.js";
import type { OpenClawPluginToolContext } from "./types.js";
import { normalizeToolName } from "../agents/tool-policy.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { loadOpenClawPlugins } from "./loader.js";

const log = createSubsystemLogger("plugins");

type PluginToolMeta = {
  pluginId: string;
  optional: boolean;
  source?: unknown;
};

const pluginToolMeta = new WeakMap<AnyAgentTool, PluginToolMeta>();

export function getPluginToolMeta(tool: AnyAgentTool): PluginToolMeta | undefined {
  return pluginToolMeta.get(tool);
}

function normalizeAllowlist(list?: string[]) {
  return new Set((list ?? []).map(normalizeToolName).filter(Boolean));
}

function isOptionalToolAllowed(params: {
  toolName: string;
  pluginId: string;
  allowlist: Set<string>;
}): boolean {
  if (params.allowlist.size === 0) {
    return false;
  }
  const toolName = normalizeToolName(params.toolName);
  if (params.allowlist.has(toolName)) {
    return true;
  }
  const pluginKey = normalizeToolName(params.pluginId);
  if (params.allowlist.has(pluginKey)) {
    return true;
  }
  return params.allowlist.has("group:plugins");
}

function safeSourceString(source: unknown): string {
  if (!source) return "unknown";
  if (typeof source === "string") return source;
  try {
    return JSON.stringify(source);
  } catch {
    return String(source);
  }
}

export function resolvePluginTools(params: {
  context: OpenClawPluginToolContext;
  existingToolNames?: Set<string>;
  toolAllowlist?: string[];
}): AnyAgentTool[] {
  const registry = loadOpenClawPlugins({
    config: params.context.config,
    workspaceDir: params.context.workspaceDir,
    logger: {
      info: (msg) => log.info(msg),
      warn: (msg) => log.warn(msg),
      error: (msg) => log.error(msg),
      debug: (msg) => log.debug(msg),
    },
  });

  const tools: AnyAgentTool[] = [];
  const existing = params.existingToolNames ?? new Set<string>();

  // existingNormalized: normalized(core/client/tools) name set
  const existingNormalized = new Set<string>(Array.from(existing, (t) => normalizeToolName(t)));

  // Track who "owns" a normalized tool name, so conflicts print useful provenance
  // owner = { kind: "core" | "plugin", pluginId?, source?, rawName? }
  const ownerByNormalizedName = new Map<
    string,
    { kind: "core" | "plugin"; pluginId?: string; source?: unknown; rawName?: string }
  >();

  // Seed owner map with existing tool names as "core"
  for (const raw of existing) {
    const n = normalizeToolName(raw);
    if (!n) continue;
    if (!ownerByNormalizedName.has(n)) {
      ownerByNormalizedName.set(n, { kind: "core", rawName: raw });
    }
  }

  const allowlist = normalizeAllowlist(params.toolAllowlist);
  const blockedPlugins = new Set<string>();

  for (const entry of registry.tools) {
    if (blockedPlugins.has(entry.pluginId)) {
      continue;
    }

    // Normalize plugin id to avoid collision with core tool names
    const pluginIdKey = normalizeToolName(entry.pluginId);
    if (pluginIdKey && existingNormalized.has(pluginIdKey)) {
      const message = `plugin id conflicts with core tool name (${entry.pluginId})`;
      log.error(`${message} source=${safeSourceString(entry.source)} normalized=${pluginIdKey}`);
      registry.diagnostics.push({
        level: "error",
        pluginId: entry.pluginId,
        source: entry.source,
        message,
      });
      blockedPlugins.add(entry.pluginId);
      continue;
    }

    let resolved: AnyAgentTool | AnyAgentTool[] | null | undefined = null;
    try {
      resolved = entry.factory(params.context);
    } catch (err) {
      log.error(
        `plugin tool failed (${entry.pluginId}) source=${safeSourceString(entry.source)}: ${String(
          err,
        )}`,
      );
      continue;
    }
    if (!resolved) {
      continue;
    }

    const listRaw = Array.isArray(resolved) ? resolved : [resolved];
    const list = entry.optional
      ? listRaw.filter((tool) =>
          isOptionalToolAllowed({
            toolName: tool.name,
            pluginId: entry.pluginId,
            allowlist,
          }),
        )
      : listRaw;

    if (list.length === 0) {
      continue;
    }

    // Detect duplicates within the plugin itself by normalized name
    const pluginLocalNormalized = new Set<string>();

    for (const tool of list) {
      const rawName = tool?.name ?? "";
      const normalizedName = normalizeToolName(rawName);

      if (!normalizedName) {
        const message = `plugin tool has empty/invalid name (${entry.pluginId})`;
        log.error(
          `${message} raw=${JSON.stringify(rawName)} source=${safeSourceString(entry.source)}`,
        );
        registry.diagnostics.push({
          level: "error",
          pluginId: entry.pluginId,
          source: entry.source,
          message,
        });
        continue;
      }

      // Conflict inside the same plugin (after normalize)
      if (pluginLocalNormalized.has(normalizedName)) {
        const message = `plugin provides duplicate tool name after normalize (${entry.pluginId}): ${rawName}`;
        log.error(
          `${message} normalized=${normalizedName} source=${safeSourceString(entry.source)}`,
        );
        registry.diagnostics.push({
          level: "error",
          pluginId: entry.pluginId,
          source: entry.source,
          message,
        });
        continue;
      }
      pluginLocalNormalized.add(normalizedName);

      // Conflict with existing tools (core/client/previous plugins) by normalized name
      if (existingNormalized.has(normalizedName)) {
        const prev = ownerByNormalizedName.get(normalizedName);
        const prevDesc = prev
          ? prev.kind === "plugin"
            ? `plugin:${prev.pluginId} source=${safeSourceString(prev.source)} raw=${JSON.stringify(
                prev.rawName,
              )}`
            : `core raw=${JSON.stringify(prev.rawName)}`
          : "unknown";

        const message = `plugin tool name conflict (${entry.pluginId}): ${rawName}`;
        log.error(
          `${message} normalized=${normalizedName} thisSource=${safeSourceString(
            entry.source,
          )} prev=${prevDesc}`,
        );
        registry.diagnostics.push({
          level: "error",
          pluginId: entry.pluginId,
          source: entry.source,
          message,
        });

        // IMPORTANT: skip the conflicting tool (do not add)
        continue;
      }

      // OK: register tool
      existingNormalized.add(normalizedName);
      existing.add(rawName);

      ownerByNormalizedName.set(normalizedName, {
        kind: "plugin",
        pluginId: entry.pluginId,
        source: entry.source,
        rawName,
      });

      pluginToolMeta.set(tool, {
        pluginId: entry.pluginId,
        optional: entry.optional,
        source: entry.source,
      });

      tools.push(tool);
    }
  }

  return tools;
}
