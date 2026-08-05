package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/release"
)

// runRelease implements `fleetctl release <keygen|build>` — the offline publisher
// tooling that produces the signed .fleetup upgrade bundles the in-UI updater applies.
func runRelease(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fleetctl release <keygen|build> [flags]")
	}
	switch args[0] {
	case "keygen":
		return releaseKeygen(args[1:])
	case "build":
		return releaseBuild(args[1:])
	case "verify":
		return releaseVerify(args[1:])
	case "channel":
		return releaseChannel(args[1:])
	default:
		return fmt.Errorf("unknown release subcommand %q (want keygen|build|verify|channel)", args[0])
	}
}

// releaseChannel builds and signs a release-channel index from one or more .fleetup
// bundles, for hosting at FLEET_UPDATE_CHANNEL_URL so instances can "check for
// updates". Each bundle's URL is base-url + its filename. Writes <out> and <out>.sig.
func releaseChannel(args []string) error {
	fs := flag.NewFlagSet("release channel", flag.ContinueOnError)
	keyPath := fs.String("key", "", "base64 Ed25519 private key from `release keygen` (required)")
	baseURL := fs.String("base-url", "", "URL prefix the bundles are hosted under, e.g. https://releases.example.com/ (required)")
	out := fs.String("out", "channel.json", "output index path (also writes <out>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundles := fs.Args()
	if *keyPath == "" || *baseURL == "" || len(bundles) == 0 {
		//lint:ignore ST1005 a usage line ends in an ellipsis because the argument repeats
		return fmt.Errorf("usage: fleetctl release channel --key <priv> --base-url <url> [--out channel.json] <bundle.fleetup>...")
	}
	keyB, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	priv, err := release.ParsePrivateKey(strings.TrimSpace(string(keyB)))
	if err != nil {
		return err
	}
	prefix := *baseURL
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	idx := release.ChannelIndex{SchemaVersion: release.ChannelSchema}
	for _, b := range bundles {
		m, err := release.ReadManifestUnverified(b)
		if err != nil {
			return fmt.Errorf("%s: %w", b, err)
		}
		fi, err := os.Stat(b)
		if err != nil {
			return err
		}
		idx.Releases = append(idx.Releases, release.ChannelRelease{
			Version: m.Version, MinFromVersion: m.MinFromVersion,
			BundleURL: prefix + filepath.Base(b), BundleSize: fi.Size(),
			MigrationCompatibility: m.MigrationCompatibility, Notes: m.Notes, PublishedAt: m.BuildDate,
		})
		if idx.Latest == "" || release.NewerVersion(m.Version, idx.Latest) {
			idx.Latest = m.Version
		}
	}

	body, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	sig := release.Sign(body, priv)
	if err := os.WriteFile(*out+".sig", []byte(release.EncodeSig(sig)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d release(s), latest %s) + %s.sig\nHost both at %s\n", *out, len(idx.Releases), idx.Latest, *out, *baseURL)
	return nil
}

// releaseVerify checks a bundle's signature + image digests against a trusted public
// key (or FLEET_RELEASE_TRUST_KEYS) and prints its manifest. Read-only; safe for CI.
func releaseVerify(args []string) error {
	fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "path to the .fleetup bundle (required)")
	pubKeys := fs.String("keys", os.Getenv("FLEET_RELEASE_TRUST_KEYS"), "base64 trusted public key(s), comma-separated (default $FLEET_RELEASE_TRUST_KEYS)")
	extract := fs.Bool("extract", false, "also extract + digest-verify the images to a temp dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundle == "" {
		return fmt.Errorf("release verify requires --bundle")
	}
	trusted, err := release.TrustedKeys(*pubKeys)
	if err != nil {
		return err
	}
	b, err := release.Open(*bundle, trusted)
	if err != nil {
		return err
	}
	defer b.Close()
	fmt.Printf("signature OK. version=%s from>=%s migrations=%s components=%s\n",
		b.Manifest.Version, b.Manifest.MinFromVersion, b.Manifest.MigrationCompatibility, strings.Join(b.Manifest.Components, ","))
	if *extract {
		dir, err := os.MkdirTemp("", "fleetup-verify-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if _, err := b.ExtractImages(dir); err != nil {
			return err
		}
		fmt.Println("all image digests OK")
	}
	return nil
}

// sliceFlag collects a repeatable string flag (e.g. --config-add A=1 --config-add B=2).
type sliceFlag []string

func (s *sliceFlag) String() string { return strings.Join(*s, ",") }
func (s *sliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// releaseKeygen generates an Ed25519 release keypair. The PRIVATE key is written to a
// file (default release.key, mode 0600) and kept offline by the publisher; the PUBLIC
// key is printed for baking into release builds (ldflags -X ...embeddedTrustKeys) or
// configuring via FLEET_RELEASE_TRUST_KEYS.
func releaseKeygen(args []string) error {
	fs := flag.NewFlagSet("release keygen", flag.ContinueOnError)
	out := fs.String("out", "release.key", "path to write the base64 private key (keep offline)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := release.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(release.EncodePrivateKey(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote private key to %s (mode 0600 — keep this offline and secret)\n\n", *out)
	fmt.Printf("public key (bake into builds / set FLEET_RELEASE_TRUST_KEYS):\n%s\n", release.EncodePublicKey(pub))
	return nil
}

// releaseBuild assembles and signs a .fleetup bundle from already-built, version-tagged
// Docker images (docker save), pinning each image's content digest in the signed
// manifest. Run `make bundle` to build+tag the images first.
func releaseBuild(args []string) error {
	fs := flag.NewFlagSet("release build", flag.ContinueOnError)
	version := fs.String("version", "", "app version this bundle installs, e.g. v0.61.0 (required)")
	from := fs.String("from", "", "minimum running version this may upgrade from, e.g. v0.55.0 (required)")
	keyPath := fs.String("key", "", "path to the base64 Ed25519 private key from `release keygen` (required)")
	out := fs.String("out", "", "output bundle path, e.g. fleet-v0.61.0.fleetup (required)")
	components := fs.String("components", "backend,frontend,grype-scanner", "comma-separated components to include")
	prefix := fs.String("image-prefix", "fleet-terminal", "image name prefix (images are <prefix>-<component>:<version>)")
	notes := fs.String("notes", "", "release notes shown in the upgrade UI")
	migrations := fs.String("migrations", "", "comma-separated migration filenames introduced (informational)")
	breaking := fs.Bool("breaking", false, "mark migrations as breaking (requires a quiesced maintenance window; default additive)")
	buildDate := fs.String("build-date", "", "RFC3339 build date (default: now)")
	var configAdd, configSecret sliceFlag
	fs.Var(&configAdd, "config-add", "add an env key if absent: KEY=VALUE (repeatable; merged into .env by the updater)")
	fs.Var(&configSecret, "config-secret", "add an env key with a generated 32-byte hex secret if absent: KEY (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var configAdditions []release.ConfigAddition
	for _, kv := range configAdd {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--config-add %q must be KEY=VALUE", kv)
		}
		configAdditions = append(configAdditions, release.ConfigAddition{Key: k, Default: v})
	}
	for _, k := range configSecret {
		configAdditions = append(configAdditions, release.ConfigAddition{Key: k, Generate: "secret"})
	}
	if *version == "" || *from == "" || *keyPath == "" || *out == "" {
		return fmt.Errorf("release build requires --version, --from, --key and --out")
	}
	keyB, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	priv, err := release.ParsePrivateKey(strings.TrimSpace(string(keyB)))
	if err != nil {
		return err
	}

	staging, err := os.MkdirTemp("", "fleetup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	var images []release.ImageRef
	imageFiles := map[string]string{}
	for _, comp := range splitCSV(*components) {
		ref := fmt.Sprintf("%s-%s:%s", *prefix, comp, *version)
		tarPath := filepath.Join(staging, comp+".tar")
		fmt.Printf("docker save %s ...\n", ref)
		if err := dockerSave(ref, tarPath); err != nil {
			return fmt.Errorf("save %s (is it built and tagged? run `make bundle`): %w", ref, err)
		}
		digest, size, err := release.HashFile(tarPath)
		if err != nil {
			return err
		}
		inBundle := "images/" + comp + ".tar"
		images = append(images, release.ImageRef{
			Component: comp, Image: fmt.Sprintf("%s-%s", *prefix, comp), Tag: *version,
			File: inBundle, Digest: digest, Bytes: size,
		})
		imageFiles[inBundle] = tarPath
	}

	compat := release.CompatAdditive
	if *breaking {
		compat = release.CompatBreaking
	}
	date := *buildDate
	if date == "" {
		date = time.Now().UTC().Format(time.RFC3339)
	}
	m := release.Manifest{
		SchemaVersion: release.ManifestSchema, Version: *version, BuildDate: date,
		MinFromVersion: *from, Components: splitCSV(*components), Images: images,
		Migrations: splitCSV(*migrations), MigrationCompatibility: compat, Notes: *notes,
		ConfigAdditions: configAdditions,
	}
	if err := m.Validate(); err != nil {
		return err
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sig := release.Sign(mj, priv)

	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := release.WriteBundle(f, mj, sig, imageFiles); err != nil {
		return err
	}
	fmt.Printf("\nwrote signed bundle %s (%s, %d image(s), %s migrations)\n", *out, *version, len(images), compat)
	return nil
}

func dockerSave(ref, dest string) error {
	cmd := exec.Command("docker", "save", "-o", dest, ref)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
