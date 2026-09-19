package monitor

import "testing"

// Every network filesystem spells its server differently, and getting one wrong does
// not fail visibly: it invents a dependency on whichever host happens to share a
// name with a path component, and that edge then decides what a blast-radius preview
// warns about.
func TestMountServerPerFilesystem(t *testing.T) {
	cases := map[string]string{
		"nas:/tank/media":         "nas",
		"NAS.example.com:/export": "nas.example.com",
		"10.10.0.9:/tank/vm":       "10.10.0.9",
		"[fd00::1]:/export":       "fd00::1",
		"//nas/share":             "nas",
		`\\nas\share`:             "nas",
		"mon1,mon2,mon3:/":        "mon1",
		"1.2.3.4:6789:/":          "1.2.3.4",
		// Nothing to name: these must produce no server rather than a guess.
		"/dev/sda1": "",
		"tmpfs":     "",
		"overlay":   "",
		"nas:":      "",
		":/export":  "",
	}
	for src, want := range cases {
		if got := mountServer(src); got != want {
			t.Errorf("mountServer(%q) = %q, want %q", src, got, want)
		}
	}
}

// A real /proc/self/mounts, with the virtualisation answer appended. Only network
// filesystems are dependencies; every local mount in here must be ignored, because
// a suggestion for "overlay" or "tmpfs" is noise that teaches people to dismiss the
// panel.
func TestParseMountsKeepsOnlyNetworkFilesystems(t *testing.T) {
	out := `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/mapper/vg-root / ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1608044k 0 0
10.10.0.9:/tank/media /mnt/media nfs4 rw,relatime,vers=4.2,addr=10.10.0.9 0 0
nas:/tank/backup /mnt/my\040backup nfs rw,relatime 0 0
//fileserver/docs /mnt/docs cifs rw,relatime 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw,relatime 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw,relatime 0 0
---virt---
kvm
`
	mounts, virt := parseMounts(out)
	if virt != "kvm" {
		t.Errorf("virt = %q, want kvm", virt)
	}
	if len(mounts) != 3 {
		t.Fatalf("got %d mounts, want 3: %+v", len(mounts), mounts)
	}
	if mounts[0].Server != "10.10.0.9" || mounts[0].FSType != "nfs4" || mounts[0].Target != "/mnt/media" {
		t.Errorf("nfs4 mount wrong: %+v", mounts[0])
	}
	// The kernel escapes a space as \040; a path printed with the escape still in it
	// is a path an operator cannot find.
	if mounts[1].Target != "/mnt/my backup" {
		t.Errorf("escaped path not decoded: %q", mounts[1].Target)
	}
	if mounts[2].Server != "fileserver" || mounts[2].FSType != "cifs" {
		t.Errorf("cifs mount wrong: %+v", mounts[2])
	}
}

// "none" is systemd's answer for bare metal. Storing it would make every physical
// host look like a guest of something.
func TestParseMountsTreatsNoneAsNotVirtualised(t *testing.T) {
	if _, virt := parseMounts("---virt---\nnone\n"); virt != "" {
		t.Errorf("virt = %q, want empty for bare metal", virt)
	}
	// An older host has no systemd-detect-virt at all: absent, not "none", and
	// still not an error.
	if m, virt := parseMounts("tmpfs /run tmpfs rw 0 0\n---virt---\n"); virt != "" || len(m) != 0 {
		t.Errorf("missing detector produced %q / %+v", virt, m)
	}
}
