import { describe, expect, it } from "vitest";
import { listeningNotReachable, netSevColor, type NetScan } from "./netscan";

function scan(p: Partial<NetScan>): NetScan {
  return {
    id: "x", runId: "r", hostId: "h", target: "10.0.0.5", path: "lan", requester: "t", scheduled: false,
    status: "completed", openPorts: 0, total: 0, critical: 0, high: 0, medium: 0, low: 0, unexpected: 0,
    listenersKnown: true, durationSec: 0, createdAt: "", ...p,
  };
}

describe("listeningNotReachable", () => {
  it("lists exposed listeners no path reached, once each", () => {
    const lan = scan({
      id: "lan",
      listeners: [
        { proto: "tcp", address: "0.0.0.0", port: 22, exposed: true, process: "sshd" },
        { proto: "tcp", address: "0.0.0.0", port: 5432, exposed: true, process: "postgres" },
        { proto: "tcp", address: "::", port: 5432, exposed: true, process: "postgres" },
        { proto: "tcp", address: "127.0.0.1", port: 6379, exposed: false, process: "redis" },
      ],
      services: [{ port: 22, proto: "tcp", tls: false, unexpected: false }],
    });
    const ov = scan({ id: "ov", path: "overlay", services: [{ port: 443, proto: "tcp", tls: true, unexpected: false }] });
    const got = listeningNotReachable(lan, [lan, ov]).map((l) => `${l.proto}/${l.port}`);
    expect(got).toEqual(["tcp/5432"]);
  });

  it("is empty when the listener list was never collected", () => {
    expect(listeningNotReachable(scan({ listenersKnown: false }), [])).toEqual([]);
  });

  // An unreachable path reached nothing, but it must not make every listener look
  // firewalled either: only completed scans count as having looked.
  it("ignores services of scans that did not complete", () => {
    const s = scan({
      listeners: [{ proto: "tcp", address: "0.0.0.0", port: 22, exposed: true }],
      services: [],
    });
    const failed = scan({ id: "f", status: "unreachable", services: [{ port: 22, proto: "tcp", tls: false, unexpected: false }] });
    expect(listeningNotReachable(s, [s, failed]).map((l) => l.port)).toEqual([22]);
  });
});

describe("netSevColor", () => {
  it("maps severities", () => {
    expect(netSevColor("critical")).toBe("error");
    expect(netSevColor("medium")).toBe("warning");
    expect(netSevColor(undefined)).toBe("default");
  });
});
