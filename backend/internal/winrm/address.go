package winrm

// ManagementAddrs orders the addresses a Windows host can be managed on.
//
// The overlay address comes first once the host is on the overlay, and is left out
// entirely until then. That exception is the whole point of this function.
//
// Fetching a Windows enrollment script ASSIGNS and PERSISTS an overlay address before
// the operator has run anything: the script has to contain the address the host will
// hold, and the finish step has to agree with it. Every WinRM path then preferred that
// address, because it was set. But no peer exists on the jump host until the operator
// runs the script and pastes the public key back — which is minutes later at best, and
// commonly the next day, since fetching the script and walking to the machine are
// separate acts.
//
// In between, the host silently dropped out of management. Fact collection, vulnerability
// scanning and script runs all dialled an address with no route behind it and failed with
//
//	no reachable WinRM port: ssh: rejected: connect failed ("No route to host")
//
// on a host that was sitting there answering on its ordinary address the whole time.
// Observed on a live Windows Server 2025 host: automations ran fine, an enrollment
// script was fetched and never finished, and the identical automation then failed.
//
// Callers that try every candidate in turn were only slow. Callers that took the first
// one were broken.
func ManagementAddrs(overlayAddr, address, hostname string, enrolled bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if enrolled {
		add(overlayAddr)
	}
	add(address)
	add(hostname)
	// A host that is enrolled and has nothing else is still reachable on the overlay.
	if len(out) == 0 {
		add(overlayAddr)
	}
	return out
}

// ManagementAddr is ManagementAddrs' first choice, for callers that dial exactly one.
func ManagementAddr(overlayAddr, address, hostname string, enrolled bool) string {
	if a := ManagementAddrs(overlayAddr, address, hostname, enrolled); len(a) > 0 {
		return a[0]
	}
	return hostname
}
