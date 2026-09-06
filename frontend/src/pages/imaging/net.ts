// Subnet arithmetic for the provisioning page, kept out of the component file so
// it can be tested (and so fast refresh keeps working there).

// rangeWithin derives a DHCP lease range inside a NIC's own subnet, so standalone
// DHCP needs no manual arithmetic from whoever is setting it up.
//
// The offsets are `min(100, size/4)` and `min(200, size-2)` — deliberately the
// same formula Flipside uses in both its TypeScript and its Python, so the two
// never propose different ranges for the same NIC. On a /24 the quarter-way rule
// wins, so a range starts at .64 rather than .100.
//
// Returns null for anything that cannot host PXE clients: a /31 or /32, or a
// malformed network. Emitting a range for those would produce a DHCP config that
// can never lease anything.
export function rangeWithin(
  network: string,
  prefixlen: number,
): { start: string; end: string } | null {
  const base = network.split(".").map(Number);
  if (base.length !== 4 || base.some((n) => Number.isNaN(n))) return null;
  const size = 2 ** (32 - prefixlen);
  if (size < 8) return null;
  // Unsigned throughout: a first octet above 127 overflows a signed 32-bit shift
  // and would come back negative, giving wrong octets for every 192.x and 10.x
  // network — which is most of them.
  const at = (off: number) => {
    const v = (((base[0] << 24) >>> 0) + (base[1] << 16) + (base[2] << 8) + base[3] + off) >>> 0;
    return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".");
  };
  return { start: at(Math.min(100, Math.floor(size / 4))), end: at(Math.min(200, size - 2)) };
}
