package release

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Bundle entry names. The manifest and its signature MUST be the first two entries so
// a reader can verify the signature before streaming any image payload.
const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig"
	imageDir     = "images"
)

// HashFile returns the "sha256:<hex>" digest and byte length of a file.
func HashFile(path string) (digest string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// WriteBundle assembles a signed bundle tar: manifest.json, manifest.sig, then each
// image file (keyed by its in-bundle path, e.g. "images/backend.tar", to an on-disk
// source path). The manifest must already pin each image's digest (compute with
// HashFile before signing) and sig must be Sign(manifestJSON, priv) over the SAME
// bytes written here.
func WriteBundle(out io.Writer, manifestJSON, sig []byte, imageFiles map[string]string) error {
	tw := tar.NewWriter(out)
	if err := writeTarBytes(tw, manifestName, manifestJSON); err != nil {
		return err
	}
	if err := writeTarBytes(tw, sigName, sig); err != nil {
		return err
	}
	// Deterministic order for reproducibility.
	names := make([]string, 0, len(imageFiles))
	for n := range imageFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeTarFile(tw, name, imageFiles[name]); err != nil {
			return err
		}
	}
	return tw.Close()
}

// ReadManifestUnverified reads a bundle's manifest WITHOUT verifying its signature.
// For PUBLISHER-side tooling only (building a channel index from your own bundles);
// never use it to decide whether to apply a bundle — use Open for that.
func ReadManifestUnverified(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != manifestName {
		return Manifest{}, fmt.Errorf("bundle: expected %s as the first entry", manifestName)
	}
	data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Bundle is an opened, signature-verified bundle. Image payloads are NOT yet read;
// call ExtractImages to stream and digest-verify them.
type Bundle struct {
	Manifest Manifest
	tr       *tar.Reader
	closer   io.Closer
}

// Open reads a bundle from path, verifies its signature against the trusted keys, and
// validates the manifest. On success the returned Bundle is positioned to stream the
// image entries. Caller must Close it.
func Open(path string, trusted []ed25519.PublicKey) (*Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := openReader(f, trusted)
	if err != nil {
		f.Close()
		return nil, err
	}
	b.closer = f
	return b, nil
}

// openReader is the io.Reader-based core of Open (separated for tests).
func openReader(r io.Reader, trusted []ed25519.PublicKey) (*Bundle, error) {
	tr := tar.NewReader(r)

	// Entry 1: manifest.json
	hdr, err := tr.Next()
	if err != nil || hdr.Name != manifestName {
		return nil, fmt.Errorf("bundle: expected %s as the first entry", manifestName)
	}
	manifestJSON, err := io.ReadAll(io.LimitReader(tr, 1<<20)) // 1 MiB cap; manifests are tiny
	if err != nil {
		return nil, fmt.Errorf("bundle: read manifest: %w", err)
	}

	// Entry 2: manifest.sig
	hdr, err = tr.Next()
	if err != nil || hdr.Name != sigName {
		return nil, fmt.Errorf("bundle: expected %s as the second entry", sigName)
	}
	sig, err := io.ReadAll(io.LimitReader(tr, 4096))
	if err != nil {
		return nil, fmt.Errorf("bundle: read signature: %w", err)
	}

	// Verify signature BEFORE trusting anything in the manifest.
	if err := Verify(manifestJSON, sig, trusted); err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	return &Bundle{Manifest: m, tr: tr}, nil
}

// ExtractImages streams each image entry out to destDir, verifying its content digest
// against the (already signature-authenticated) manifest as it writes. Any missing,
// extra, or digest-mismatched image is a hard error and destDir should be discarded.
// Returns the on-disk paths keyed by component.
func (b *Bundle) ExtractImages(destDir string) (map[string]string, error) {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, err
	}
	byFile := make(map[string]ImageRef, len(b.Manifest.Images))
	for _, im := range b.Manifest.Images {
		byFile[im.File] = im
	}
	seen := make(map[string]bool)
	out := make(map[string]string)
	for {
		hdr, err := b.tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read image entry: %w", err)
		}
		im, ok := byFile[hdr.Name]
		if !ok {
			return nil, fmt.Errorf("bundle: unexpected entry %q not in manifest", hdr.Name)
		}
		dest := filepath.Join(destDir, filepath.Base(hdr.Name))
		digest, n, err := copyAndHash(dest, b.tr)
		if err != nil {
			return nil, err
		}
		if digest != im.Digest {
			return nil, fmt.Errorf("bundle: image %s digest mismatch (manifest %s, actual %s)", im.Component, im.Digest, digest)
		}
		if im.Bytes != 0 && n != im.Bytes {
			return nil, fmt.Errorf("bundle: image %s size mismatch (manifest %d, actual %d)", im.Component, im.Bytes, n)
		}
		seen[hdr.Name] = true
		out[im.Component] = dest
	}
	for _, im := range b.Manifest.Images {
		if !seen[im.File] {
			return nil, fmt.Errorf("bundle: manifest image %s (%s) is missing from the bundle", im.Component, im.File)
		}
	}
	return out, nil
}

func (b *Bundle) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

func copyAndHash(dest string, r io.Reader) (digest string, n int64, err error) {
	f, err := os.Create(dest)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err = io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

func writeTarBytes(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeTarFile(tw *tar.Writer, name, srcPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: st.Size(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
