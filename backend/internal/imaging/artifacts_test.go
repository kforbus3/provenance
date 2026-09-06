package imaging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kforbus3/blackfriars/backend/internal/config"
)

// svcWithOutput builds a Service whose artifact directory is a temp dir, which is
// all ImagerArches reads.
func svcWithOutput(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	return &Service{cfg: &config.Config{ArtifactDir: dir}}, dir
}

func writeImager(t *testing.T, dir string, files ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Nothing built is the state a fresh server is in, and it must report as such
// rather than as an error — the provisioning preflight turns this into "build the
// imager first", which is the whole reason PXE cannot start yet.
func TestImagerArchesReportsNothingBuilt(t *testing.T) {
	s, _ := svcWithOutput(t)
	got := s.ImagerArches()
	if got["amd64"] || got["arm64"] {
		t.Errorf("ImagerArches() = %v, want both false on an empty output dir", got)
	}
}

// amd64 lives at the top of the imager directory — where it always has, so a
// server predating arm64 support keeps working untouched.
func TestImagerArchesFindsAmd64AtTheTop(t *testing.T) {
	s, dir := svcWithOutput(t)
	writeImager(t, filepath.Join(dir, "imager"), "vmlinuz", "initramfs.img")
	got := s.ImagerArches()
	if !got["amd64"] {
		t.Errorf("amd64 = false, want true when imager/vmlinuz and imager/initramfs.img exist")
	}
	if got["arm64"] {
		t.Errorf("arm64 = true, want false — nothing was built for it")
	}
}

// Other architectures get a subdirectory, and a machine picks its own at boot
// from iPXE's ${buildarch}, so both can be present and neither interferes.
func TestImagerArchesFindsArm64InItsSubdirectory(t *testing.T) {
	s, dir := svcWithOutput(t)
	writeImager(t, filepath.Join(dir, "imager", "arm64"), "vmlinuz", "initramfs.img")
	got := s.ImagerArches()
	if !got["arm64"] {
		t.Errorf("arm64 = false, want true")
	}
	if got["amd64"] {
		t.Errorf("amd64 = true, want false — the arm64 subdirectory is not the amd64 one")
	}
}

// A half-built imager is not a built one. An interrupted build leaves the kernel
// without its initramfs, and reporting that as ready sends a machine to PXE-boot
// something it cannot complete.
func TestImagerArchesRequiresBothFiles(t *testing.T) {
	for _, only := range []string{"vmlinuz", "initramfs.img"} {
		s, dir := svcWithOutput(t)
		writeImager(t, filepath.Join(dir, "imager"), only)
		if s.ImagerArches()["amd64"] {
			t.Errorf("amd64 = true with only %s present, want false", only)
		}
	}
}

// A directory named vmlinuz is not a kernel.
func TestImagerArchesIgnoresDirectories(t *testing.T) {
	s, dir := svcWithOutput(t)
	base := filepath.Join(dir, "imager")
	if err := os.MkdirAll(filepath.Join(base, "vmlinuz"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeImager(t, base, "initramfs.img")
	if s.ImagerArches()["amd64"] {
		t.Error("amd64 = true when vmlinuz is a directory, want false")
	}
}

// A missing output directory is a fresh server, not a failure.
func TestImagerArchesSurvivesAMissingOutputDir(t *testing.T) {
	s := &Service{cfg: &config.Config{ArtifactDir: filepath.Join(t.TempDir(), "nope")}}
	got := s.ImagerArches()
	if got["amd64"] || got["arm64"] {
		t.Errorf("ImagerArches() = %v, want both false", got)
	}
}
