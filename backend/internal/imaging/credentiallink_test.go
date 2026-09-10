package imaging

import (
	"regexp"
	"testing"
)

// The credential a machine actually needs is the one for the image it was
// IMAGED from — not the image it is running now.
//
// A machine's LUKS header is written once, at imaging time. RAUC writes through
// /dev/mapper/luks-rootfs-*, so installing a bundle built from a newer image
// replaces the operating system and leaves the keyslots exactly as the original
// image made them. Nothing about a machine's current version points back to the
// credential that opens its disk, which is what makes deleting an old image's
// credential the quiet, irreversible mistake.
//
// The link is a join, and the join is a string match between two values written
// by different code paths:
//
//	imaging_machines.image  http://192.168.50.1/images/almalinux-9-amd64-ab.img.zst
//	vault_secrets.target    almalinux-9-amd64-ab.img
//
// secretNameForImage is what produced the second. MachinesImagedFrom reproduces
// it in SQL. If the two ever stop agreeing the join returns nothing, the delete
// guard waves the deletion through, and the failure is silent in the worst
// possible direction — so pin them to each other.

// sqlNormalise is the SQL in store.MachinesImagedFrom, expressed here so the two
// can be compared on the same inputs.
func sqlNormalise(image string) string {
	image = regexp.MustCompile(`^.*/`).ReplaceAllString(image, "")
	return regexp.MustCompile(`[.](zst|gz)$`).ReplaceAllString(image, "")
}

func TestTheJoinMatchesTheNameCredentialsAreFiledUnder(t *testing.T) {
	// The middle column is what a machine records: the URL the imager fetched.
	for _, image := range []string{
		"http://192.168.50.1/images/almalinux-9-amd64-ab.img.zst",
		"http://192.168.50.1/images/almalinux-9-amd64-ab-2.img.zst",
		"https://prov.example.com/images/rocky-9-amd64-ab.img.gz",
		"/output/rocky-9-amd64-ab.img",
		"plain-name.img",
	} {
		filed := secretNameForImage(image)
		joined := sqlNormalise(image)
		if filed != joined {
			t.Errorf("image %q: credential is filed under %q but the SQL join looks for %q — "+
				"machines depending on that credential would be invisible, and the delete "+
				"guard would let it be removed", image, filed, joined)
		}
	}
}

// The specific pairing from the live deployment, so a regression is recognisable
// rather than abstract.
func TestKnownMachineResolvesToItsCredential(t *testing.T) {
	const imaged = "http://192.168.50.1/images/almalinux-9-amd64-ab.img.zst"
	if got := "luks/" + secretNameForImage(imaged); got != "luks/almalinux-9-amd64-ab.img" {
		t.Errorf("credential for a machine imaged from %q = %q", imaged, got)
	}
	// And it must NOT resolve to the newer image's credential, which is the
	// confusion this exists to prevent: the machine may well be running a bundle
	// built from -2 and still open only with the original passphrase.
	if secretNameForImage(imaged) == "almalinux-9-amd64-ab-2.img" {
		t.Error("a machine imaged from the original image resolved to the newer image's credential")
	}
}
