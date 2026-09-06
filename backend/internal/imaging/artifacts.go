package imaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The artefact library: the images the builder has produced and the update
// bundles made from them.
//
// Read off disk rather than tracked in the database. The builder writes an image
// and a sidecar beside it; the provisioning server serves the same directory.
// A second copy of "which images exist" in a table would be a thing that drifts
// from the directory whenever a file is removed by hand, and the directory is
// the one an operator can actually see.

// Image is a built A/B disk image.
type Image struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
	SHA256  string    `json:"sha256,omitempty"`

	Distro     string `json:"distro,omitempty"`
	Suite      string `json:"suite,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Version    string `json:"version,omitempty"`
	Encrypted  bool   `json:"encrypted"`
	SecureBoot bool   `json:"secureBoot"`
	Packages   int    `json:"packages,omitempty"`
	HasSBOM    bool   `json:"hasSbom"`
}

// Bundle is a signed RAUC update bundle.
type Bundle struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	Created     time.Time `json:"created"`
	Version     string    `json:"version,omitempty"`
	Compatible  string    `json:"compatible,omitempty"`
	Source      string    `json:"source,omitempty"`
	Description string    `json:"description,omitempty"`
	IsLatest    bool      `json:"isLatest"`
	HasSBOM     bool      `json:"hasSbom"`
}

// imageSidecar is what the builder writes beside an image. Only the fields read
// here are named; the builder records more, and mirroring all of it would be a
// second schema to keep in step for no gain.
type imageSidecar struct {
	Distro     string `json:"distro"`
	Suite      string `json:"suite"`
	Arch       string `json:"arch"`
	Profile    string `json:"profile"`
	Version    string `json:"version"`
	Encrypted  bool   `json:"encrypted"`
	SecureBoot bool   `json:"secure_boot"`
	Packages   int    `json:"packages"`
	Created    string `json:"created"`
}

type bundleSidecar struct {
	Version     string `json:"version"`
	Compatible  string `json:"compatible"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

func (s *Service) artifactDir() string {
	if s.cfg.ArtifactDir != "" {
		return s.cfg.ArtifactDir
	}
	return "/output"
}

func (s *Service) bundleDir() string { return filepath.Join(s.artifactDir(), "bundles") }

// ImagerArches reports which architectures have a netboot imager built.
//
// The imager is the kernel and initramfs a machine downloads and executes to be
// imaged at all, so without one PXE boots into nothing — which is why the
// provisioning preflight refuses to start the server without it. It is per
// architecture because the imager IS a kernel: an amd64 imager cannot boot an
// arm64 machine however it is served.
//
// amd64 lives at the top of the imager directory, where it always has, so a
// server predating arm64 support keeps working untouched; other architectures
// get a subdirectory. A machine picks its own at boot from iPXE's ${buildarch},
// so both can be present and neither interferes.
func (s *Service) ImagerArches() map[string]bool {
	built := func(dir string) bool {
		for _, f := range []string{"vmlinuz", "initramfs.img"} {
			st, err := os.Stat(filepath.Join(dir, f))
			if err != nil || st.IsDir() {
				return false
			}
		}
		return true
	}
	base := filepath.Join(s.artifactDir(), "imager")
	return map[string]bool{
		"amd64": built(base),
		"arm64": built(filepath.Join(base, "arm64")),
	}
}

// Images lists the built image library, newest first.
func (s *Service) Images() ([]Image, error) {
	entries, err := os.ReadDir(s.artifactDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not an error: a server that has not built anything yet has an
			// empty library, which is a fact rather than a fault.
			return nil, nil
		}
		return nil, err
	}
	var out []Image
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isImage(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		full := filepath.Join(s.artifactDir(), name)
		img := Image{Name: name, Size: info.Size(), Created: info.ModTime()}
		var side imageSidecar
		if readJSON(full+".json", &side) == nil {
			img.Distro, img.Suite, img.Arch = side.Distro, side.Suite, side.Arch
			img.Profile, img.Version = side.Profile, side.Version
			img.Encrypted, img.SecureBoot, img.Packages = side.Encrypted, side.SecureBoot, side.Packages
			if t, err := time.Parse(time.RFC3339, side.Created); err == nil {
				img.Created = t
			}
		}
		img.SHA256 = firstField(readText(full + ".sha256"))
		img.HasSBOM = exists(full + ".spdx.json")
		out = append(out, img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Bundles lists update bundles, newest first, and marks the one a machine
// running bare `ab-update` will fetch.
func (s *Service) Bundles() ([]Bundle, error) {
	entries, err := os.ReadDir(s.bundleDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	// Directory listing is off on the provisioning server, so `latest` is the
	// only way an unattended machine finds a bundle at all. Worth showing,
	// because deleting the bundle it names changes what the whole fleet gets.
	latest := strings.TrimSpace(readText(filepath.Join(s.bundleDir(), "latest")))
	var out []Bundle
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".raucb") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		full := filepath.Join(s.bundleDir(), name)
		b := Bundle{Name: name, Size: info.Size(), Created: info.ModTime(),
			IsLatest: name == latest, HasSBOM: exists(full + ".spdx.json")}
		var side bundleSidecar
		if readJSON(full+".json", &side) == nil {
			b.Version, b.Compatible = side.Version, side.Compatible
			b.Source, b.Description = side.Source, side.Description
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// BundleInfo is one bundle by name, for the checks a rollout makes before it
// starts.
func (s *Service) BundleInfo(name string) (*Bundle, error) {
	bundles, err := s.Bundles()
	if err != nil {
		return nil, fmt.Errorf("reading the bundle library: %w", err)
	}
	for i := range bundles {
		if bundles[i].Name == name {
			return &bundles[i], nil
		}
	}
	return nil, fmt.Errorf("no such bundle: %s", name)
}

func isImage(name string) bool {
	return strings.HasSuffix(name, ".img") ||
		strings.HasSuffix(name, ".img.zst") ||
		strings.HasSuffix(name, ".img.gz")
}

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func readText(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
