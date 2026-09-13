package imaging

import "testing"

// When a build must NOT leave a copy of its LUKS passphrase on this server.
//
// The build dialog offers "Generate the recovery passphrase and store it", and
// turning it off is how you build a laptop image: the operator types a
// passphrase, the machine asks for it at every boot, and Provenance keeps no copy --
// so a stolen laptop and a compromised control plane are each useless alone.
//
// That is a promise the UI makes in as many words, and it is enforced by exactly
// one condition. Getting it wrong in the permissive direction produces no error,
// no failed build and no visible symptom: the image builds, the machine boots,
// and a passphrase the operator was told is nowhere is sitting in the vault. The
// only thing standing between that and a shipped release is this test.
func TestPassphraseIsNotFiledUnlessExplicitlyAsked(t *testing.T) {
	const yes, no = true, false

	cases := []struct {
		name string
		kind string
		body map[string]any
		want bool
	}{
		{
			name: "encrypted image, operator asked to store it",
			kind: "image",
			body: map[string]any{"encrypt": yes, "generatePassphrase": yes},
			want: true,
		}, {
			// The laptop case, and the reason this file exists.
			name: "encrypted image, operator supplies their own",
			kind: "image",
			body: map[string]any{"encrypt": yes, "generatePassphrase": no},
			want: false,
		}, {
			// Absent is not the same as false to a careless reader, and this is
			// what an older client that predates the flag sends.
			name: "encrypted image, flag absent entirely",
			kind: "image",
			body: map[string]any{"encrypt": yes},
			want: false,
		}, {
			name: "unencrypted image cannot have a passphrase to file",
			kind: "image",
			body: map[string]any{"encrypt": no, "generatePassphrase": yes},
			want: false,
		}, {
			name: "encrypt absent, which is the default for a plain build",
			kind: "image",
			body: map[string]any{"generatePassphrase": yes},
			want: false,
		}, {
			// The netboot imager has no root filesystem of its own to encrypt.
			// Filing a secret for it would put an unused credential in the vault
			// under an image name that never appears.
			name: "imager build never files anything",
			kind: "imager",
			body: map[string]any{"encrypt": yes, "generatePassphrase": yes},
			want: false,
		}, {
			name: "bundle build never files anything",
			kind: "bundle",
			body: map[string]any{"encrypt": yes, "generatePassphrase": yes},
			want: false,
		}, {
			name: "empty body",
			kind: "image",
			body: map[string]any{},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldFilePassphrase(c.kind, c.body); got != c.want {
				t.Errorf("shouldFilePassphrase(%q, %v) = %v, want %v",
					c.kind, c.body, got, c.want)
			}
		})
	}
}

// The flags arrive as JSON and a client is free to send strings. "false" from a
// form-encoded client must not read as true -- that would file a passphrase the
// operator asked not to have filed, which is the one direction that fails silently.
func TestStringFlagsAreReadTheWayTheyAreMeant(t *testing.T) {
	cases := []struct {
		encrypt, generate any
		want              bool
	}{
		{"true", "true", true},
		{"true", "false", false},
		{"false", "true", false},
		{"true", "", false},
		{"true", "0", false},
		{true, "false", false},
		{"false", true, false},
	}

	for _, c := range cases {
		body := map[string]any{"encrypt": c.encrypt, "generatePassphrase": c.generate}
		if got := shouldFilePassphrase("image", body); got != c.want {
			t.Errorf("encrypt=%#v generatePassphrase=%#v: got %v, want %v",
				c.encrypt, c.generate, got, c.want)
		}
	}
}
