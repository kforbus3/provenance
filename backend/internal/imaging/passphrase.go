package imaging

import (
	"encoding/json"

	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/kforbus3/provenance/backend/internal/credresolve"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/extsecret"
	"github.com/kforbus3/provenance/backend/internal/secretbox"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Generating and filing the LUKS recovery passphrase for an image about to be
// built.
//
// The ordering is the whole point, and it is the reverse of the obvious one: the
// passphrase is stored BEFORE the build starts. Storing it afterwards would mean
// a write that fails — an expired token, a sealed store, a network blip — has
// already produced an encrypted image that nobody holds the recovery key for, and
// nothing about that image says so. Storing first can only leave an unused secret
// behind if the build then fails, which costs nothing and is visible in the
// credential list.
//
// Where it goes: the external secrets manager when one is connected, so Fleet does
// not become a second copy of record for an organization that already has one;
// otherwise Fleet's own credential vault, sealed at rest. Either way a
// vault_secrets row is created, so the passphrase is found the same way in the UI
// whichever backend holds the material.

// passphraseBytes is the entropy behind a generated recovery passphrase. 32 bytes
// is 256 bits — well past what LUKS2's argon2 needs, and this is never typed from
// memory, only copied out of the vault.
const passphraseBytes = 32

// GeneratedPassphrase is where a build's recovery passphrase ended up.
type GeneratedPassphrase struct {
	// Passphrase travels to the builder in the environment like any other. The
	// builder needs no access to the store it was filed in.
	Passphrase string
	// SecretID is the vault_secrets row, so the UI can link straight to it.
	SecretID uuid.UUID
	// Backend is "external" or "vault", and Location says where precisely — a
	// provider reference, or the credential name.
	Backend  string
	Location string
}

// generatePassphrase returns a URL-safe random passphrase.
func generatePassphrase() (string, error) {
	buf := make([]byte, passphraseBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate passphrase: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// secretNameForImage is the key an image's passphrase is filed under, independent
// of how the image was compressed.
//
// The library holds `foo.img.zst` while an uncompressed build of the same thing is
// `foo.img`; both are the same image and must resolve to one secret, or rebuilding
// with a different compression would strand the passphrase under the old name.
func secretNameForImage(image string) string {
	name := filepath.Base(strings.TrimSpace(image))
	for _, suffix := range []string{".zst", ".gz"} {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
			break
		}
	}
	return name
}

// imageNameSanitize matches the builder's own rule. The name reaches a shell
// command line, and it is also a secrets-manager path component.
var imageNameSanitize = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// FreeImageName picks the name a build should produce, so the passphrase can be
// filed under it before the build runs.
//
// The sidecar would otherwise choose this itself, and the backend cannot see its
// answer until the build has already started — too late to be sure the recovery
// key was stored first. The backend reads the same output directory (it already
// does for the image library), so it can settle the question and pass the name
// explicitly instead.
//
// Every extension is checked, not just the one this build would write: an
// uncompressed build landing beside the .zst of the same name is two different
// images with one identity, and the passphrase filed under that name would then
// be ambiguous.
func (s *Service) FreeImageName(base string) string {
	base = imageNameSanitize.ReplaceAllString(strings.TrimSpace(base), "-")
	base = strings.Trim(base, "-.")
	if base == "" {
		base = "image"
	}
	if !s.imageNameTaken(base) {
		return base + ".img"
	}
	for n := 2; n < 1000; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if !s.imageNameTaken(candidate) {
			return candidate + ".img"
		}
	}
	return base + ".img"
}

func (s *Service) imageNameTaken(base string) bool {
	for _, ext := range []string{".img", ".img.zst", ".img.gz"} {
		if _, err := os.Stat(filepath.Join(s.artifactDir(), base+ext)); err == nil {
			return true
		}
	}
	return false
}

// StoreImagePassphrase generates this build's recovery passphrase and files it.
//
// Returns an error rather than a passphrase if it could not be stored. The caller
// must then NOT start the build: an encrypted image whose key was never persisted
// is worse than no image, because it looks like a success.
func (s *Service) StoreImagePassphrase(
	ctx context.Context, imageName string, meta map[string]string, createdBy uuid.UUID,
) (*GeneratedPassphrase, error) {
	passphrase, err := generatePassphrase()
	if err != nil {
		return nil, err
	}
	name := secretNameForImage(imageName)

	fields := map[string]string{
		"passphrase": passphrase,
		"image":      name,
		"created":    time.Now().UTC().Format(time.RFC3339),
		// Spelled out because whoever reads this is standing at a machine that
		// will not boot, and a secrets manager is an unlikely place to learn what
		// a LUKS recovery slot is.
		"note": "LUKS2 recovery passphrase for this A/B image. Every machine imaged " +
			"from it accepts this passphrase on any encrypted partition. Rotating it " +
			"means re-imaging, or cryptsetup luksChangeKey on each machine.",
	}
	for k, v := range meta {
		if strings.TrimSpace(v) != "" {
			fields[k] = v
		}
	}

	in := store.VaultSecretInput{
		Name:        "luks/" + name,
		Folder:      "imaging",
		Type:        "password",
		Description: "LUKS recovery passphrase for image " + name,
		Target:      name,
		CreatedBy:   createdBy,
	}

	// External manager when one is connected: an organization that already has a
	// secrets manager should not need a second copy of record. Fleet's own vault
	// still gets a row, pointing at it, so the credential is found the same way.
	if s.cfg.ExtSecretEnabled() {
		provider, ref, perr := s.storeExternally(ctx, name, fields)
		if perr != nil {
			return nil, perr
		}
		in.ExternalProvider = provider
		in.ExternalRef = ref
		secret, cerr := s.store.CreateVaultSecret(ctx, in, "")
		if cerr != nil {
			// The material is already in the external manager under `ref`; say so,
			// because it is not lost and a retry would collide with it.
			return nil, fmt.Errorf("passphrase stored at %s but the credential record "+
				"could not be created (%w) — the build was not started", ref, cerr)
		}
		return &GeneratedPassphrase{
			Passphrase: passphrase, SecretID: secret.ID,
			Backend: "external", Location: ref,
		}, nil
	}

	key, err := s.cfg.VaultKey()
	if err != nil {
		return nil, fmt.Errorf("cannot store the recovery passphrase: %w", err)
	}
	sealed, err := secretbox.Seal(key, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("could not seal the recovery passphrase: %w", err)
	}
	secret, err := s.store.CreateVaultSecret(ctx, in, sealed)
	if err != nil {
		return nil, fmt.Errorf("could not file the recovery passphrase: %w", err)
	}
	return &GeneratedPassphrase{
		Passphrase: passphrase, SecretID: secret.ID,
		Backend: "vault", Location: in.Name,
	}, nil
}

// storeExternally writes to the configured external manager, returning the
// provider name and the reference written.
func (s *Service) storeExternally(ctx context.Context, name string, fields map[string]string) (string, string, error) {
	cfg := s.cfg.ExtSecret()
	providerName := extsecret.ProviderVaultKV
	if strings.TrimSpace(cfg.VaultAddr) == "" {
		providerName = extsecret.ProviderAWSSecrets
	}
	p, err := extsecret.New(providerName, cfg)
	if err != nil {
		return "", "", fmt.Errorf("external secrets manager: %w", err)
	}
	prefix := strings.Trim(s.cfg.ImagingSecretPrefix, "/")
	ref := name
	if prefix != "" {
		ref = prefix + "/" + name
	}
	wrote, err := extsecret.StoreIfWritable(ctx, p, ref, fields)
	if err != nil {
		return "", "", fmt.Errorf("the build was not started: its LUKS passphrase could not "+
			"be stored in the secrets manager (%w). Nothing is built until the recovery key "+
			"has somewhere to live", err)
	}
	if !wrote {
		return "", "", fmt.Errorf("the configured external secrets manager (%s) cannot store "+
			"secrets, only read them", providerName)
	}
	return providerName, ref, nil
}

// ImagePassphrase returns the recovery passphrase this server filed for an
// image, or "" when it filed none.
//
// Building an update bundle from an encrypted image means reading its root
// slot, which needs the passphrase. The server generated it, filed it, and knew
// exactly which image it belongs to — and then made the operator find it and
// paste it back in, or watch the build fail:
//
//	[bundle] ERROR: this image is encrypted; pass --luks-passphrase
//
// Empty string and nil error when nothing is filed. That is the ordinary case
// for an unencrypted image, and for an encrypted one built with "generate and
// store" turned off — where the operator holds the only copy on purpose, and
// must supply it themselves. Neither is an error here; the builder already says
// the right thing when it is handed nothing.
func (s *Service) ImagePassphrase(ctx context.Context, image string) (string, error) {
	secret, err := s.store.VaultSecretByName(ctx, "luks/"+secretNameForImage(image))
	if err != nil || secret == nil {
		return "", err
	}
	key, err := s.cfg.VaultKey()
	if err != nil {
		return "", err
	}
	pt, err := credresolve.Open(ctx, s.store, secret, key, s.cfg.ExtSecret())
	if err != nil {
		return "", fmt.Errorf("reading the recovery passphrase filed for %s: %w", image, err)
	}
	// Two shapes, because the two backends store different things. The local
	// vault seals the passphrase on its own; the external manager holds the
	// whole field set, so the passphrase has to be picked out of it.
	var fields map[string]string
	if json.Unmarshal(pt, &fields) == nil && fields["passphrase"] != "" {
		return fields["passphrase"], nil
	}
	return string(pt), nil
}
