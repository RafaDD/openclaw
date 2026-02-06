import { describe, expect, it, beforeEach } from "vitest";
import {
  clearPolicyCache,
  evaluateDestructiveCommand,
  evaluateNetworkSend,
  evaluatePathOperation,
  evaluateSecretDetection,
  loadPolicy,
} from "./policy.js";

describe("restricted-ops-policy", () => {
  describe("evaluatePathOperation", () => {
    beforeEach(() => {
      clearPolicyCache();
    });

    it("denies system-critical paths", async () => {
      const result = await evaluatePathOperation("/usr/bin/test", "delete");
      expect(result.decision).toBe("deny");
      expect(result.ruleId).toBe("system-critical-path");
    });

    it("allows non-system paths", async () => {
      const result = await evaluatePathOperation("/tmp/test.txt", "add");
      expect(result.decision).toBe("allow");
    });

    it("requires confirmation for destructive user-space operations", async () => {
      const home = process.env.HOME || process.env.USERPROFILE || "/home/test";
      const result = await evaluatePathOperation(
        `${home}/Documents/test.txt`,
        "delete",
      );
      expect(result.decision).toBe("confirm");
      expect(result.ruleId).toBe("user-space-destructive");
    });

    it("allows non-destructive operations in user-space", async () => {
      const home = process.env.HOME || process.env.USERPROFILE || "/home/test";
      const result = await evaluatePathOperation(
        `${home}/Documents/test.txt`,
        "add",
      );
      expect(result.decision).toBe("allow");
    });
  });

  describe("evaluateSecretDetection", () => {
    beforeEach(() => {
      clearPolicyCache();
    });

    it("detects high-entropy strings", async () => {
      const params = {
        apiKey: "sk_live_51H3ll0W0rld_Th1sIsAV3ryL0ngAndR4nd0mK3y",
        message: "Hello world",
      };
      const result = await evaluateSecretDetection("test_tool", params);
      expect(result.decision).toBe("confirm");
      expect(result.ruleId).toBe("secret-detection");
    });

    it("allows normal strings", async () => {
      const params = {
        message: "Hello world",
        count: 42,
      };
      const result = await evaluateSecretDetection("test_tool", params);
      expect(result.decision).toBe("allow");
    });

    it("respects field exceptions", async () => {
      const params = {
        buffer: "dGVzdGluZ19iYXNlNjRfZW5jb2RlZF9zdHJpbmdfdGhhdF9sb29rc19saWtlX2Ffc2VjcmV0",
        message: "Hello",
      };
      const result = await evaluateSecretDetection("test_tool", params);
      expect(result.decision).toBe("allow");
    });

    it("respects tool exceptions", async () => {
      const policy = loadPolicy();
      policy.secrets = {
        ...policy.secrets,
        exceptions: {
          tools: ["test_tool"],
          fields: [],
        },
      };
      const params = {
        apiKey: "sk_live_51H3ll0W0rld_Th1sIsAV3ryL0ngAndR4nd0mK3y",
      };
      const result = await evaluateSecretDetection("test_tool", params, policy);
      expect(result.decision).toBe("allow");
    });

    it("detects JWT tokens", async () => {
      const params = {
        token:
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      };
      const result = await evaluateSecretDetection("test_tool", params);
      expect(result.decision).toBe("confirm");
    });
  });

  describe("evaluateNetworkSend", () => {
    beforeEach(() => {
      clearPolicyCache();
    });

    it("denies when no allowlist configured", async () => {
      const policy = loadPolicy();
      policy.network = { allowlist: {} };
      const result = await evaluateNetworkSend("slack", "#general", policy);
      expect(result.decision).toBe("deny");
      expect(result.ruleId).toBe("network-allowlist-missing");
    });

    it("allows when recipient matches allowlist", async () => {
      const policy = loadPolicy();
      policy.network = {
        allowlist: {
          slack: ["#general", "#dev"],
        },
      };
      const result = await evaluateNetworkSend("slack", "#general", policy);
      expect(result.decision).toBe("allow");
    });

    it("denies when recipient not in allowlist", async () => {
      const policy = loadPolicy();
      policy.network = {
        allowlist: {
          slack: ["#general"],
        },
      };
      const result = await evaluateNetworkSend("slack", "#random", policy);
      expect(result.decision).toBe("deny");
      expect(result.ruleId).toBe("network-allowlist-mismatch");
    });

    it("allows domain matches in URLs", async () => {
      const policy = loadPolicy();
      policy.network = {
        allowlist: {
          webhook: ["example.com"],
        },
      };
      const result = await evaluateNetworkSend(
        "webhook",
        "https://api.example.com/webhook",
        policy,
      );
      expect(result.decision).toBe("allow");
    });
  });

  describe("evaluateDestructiveCommand", () => {
    beforeEach(() => {
      clearPolicyCache();
    });

    it("requires confirmation for destructive commands on user-space", async () => {
      const home = process.env.HOME || process.env.USERPROFILE || "/home/test";
      const result = await evaluateDestructiveCommand(
        `rm -rf ${home}/Documents/test`,
        ["rm", "-rf", `${home}/Documents/test`],
      );
      expect(result.decision).toBe("confirm");
      expect(result.ruleId).toBe("user-space-destructive-command");
    });

    it("allows non-destructive commands", async () => {
      const result = await evaluateDestructiveCommand("ls -la", ["ls", "-la"]);
      expect(result.decision).toBe("allow");
    });

    it("allows destructive commands on non-user-space paths", async () => {
      const result = await evaluateDestructiveCommand("rm /tmp/test", [
        "rm",
        "/tmp/test",
      ]);
      expect(result.decision).toBe("allow");
    });
  });

  describe("loadPolicy", () => {
    beforeEach(() => {
      clearPolicyCache();
    });

    it("loads default policy when file missing", () => {
      const policy = loadPolicy();
      expect(policy.version).toBe(1);
      expect(policy.restrictedPaths?.systemCritical).toBeDefined();
      expect(Array.isArray(policy.restrictedPaths?.systemCritical)).toBe(true);
    });

    it("caches policy after first load", () => {
      const policy1 = loadPolicy();
      const policy2 = loadPolicy();
      expect(policy1).toBe(policy2);
    });
  });
});

