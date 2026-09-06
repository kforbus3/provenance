import { describe, expect, it } from "vitest";
import { rangeWithin } from "./net";

// The DHCP lease range is derived from the chosen NIC's own subnet so nobody has
// to do the arithmetic by hand. Getting it wrong is not a cosmetic bug: a range
// outside the subnet hands out addresses machines cannot use, and one that runs
// past the broadcast address hands out addresses that are not addresses.
describe("rangeWithin", () => {
  // The offsets are `min(100, size/4)` and `min(200, size-2)` — the same formula
  // Flipside uses in both its TypeScript and its Python, kept identical so the two
  // never propose different ranges for the same NIC. On a /24 that is size/4 = 64,
  // NOT 100: the quarter-way rule wins until the subnet is larger than a /24.
  it("derives a range inside a /24, starting a quarter of the way in", () => {
    expect(rangeWithin("192.168.50.0", 24)).toEqual({
      start: "192.168.50.64",
      end: "192.168.50.200",
    });
  });

  // The offsets are capped at 100/200, so a large subnet must not walk past them
  // into a range the operator never asked for.
  it("caps the range on a large subnet rather than scaling it", () => {
    expect(rangeWithin("10.0.0.0", 16)).toEqual({
      start: "10.0.0.100",
      end: "10.0.0.200",
    });
  });

  // On a small subnet the caps are the wrong answer: 100 is outside a /28. It has
  // to scale DOWN, and must stop before the broadcast address.
  it("scales down on a small subnet and stops short of broadcast", () => {
    // /28 = 16 addresses, .0 network and .15 broadcast.
    expect(rangeWithin("192.168.1.0", 28)).toEqual({
      start: "192.168.1.4",   // size/4
      end: "192.168.1.14",    // size-2, one below broadcast
    });
  });

  // Octet arithmetic has to carry, not wrap within the last octet.
  it("carries across octet boundaries", () => {
    expect(rangeWithin("10.1.1.0", 23)).toEqual({
      start: "10.1.1.100",
      end: "10.1.1.200",
    });
    expect(rangeWithin("172.16.255.0", 24)).toEqual({
      start: "172.16.255.64",
      end: "172.16.255.200",
    });
  });

  // A /31 or /32 cannot host PXE clients at all; returning a range for one would
  // produce a DHCP config that can never lease anything.
  it("refuses subnets too small to lease from", () => {
    expect(rangeWithin("192.168.1.0", 31)).toBeNull();
    expect(rangeWithin("192.168.1.1", 32)).toBeNull();
  });

  it("refuses a malformed network rather than emitting NaN octets", () => {
    expect(rangeWithin("", 24)).toBeNull();
    expect(rangeWithin("192.168.1", 24)).toBeNull();
    expect(rangeWithin("192.168.one.0", 24)).toBeNull();
  });

  // High first octets exceed 2^31; a signed shift would make the result negative
  // and the octets wrong.
  it("handles addresses above 127 without sign overflow", () => {
    expect(rangeWithin("192.168.50.0", 24)?.start).toBe("192.168.50.64");
    expect(rangeWithin("240.0.0.0", 24)?.start).toBe("240.0.0.64");
  });
});
