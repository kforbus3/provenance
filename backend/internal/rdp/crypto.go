package rdp

// RDP recording at-rest encryption.
//
// Unlike SSH terminal recordings — which the backend writes itself and can encrypt
// frame-by-frame as the session runs (see internal/recorder) — an RDP session's
// Guacamole recording is written by the guacd sidecar, an EXTERNAL process. guacd
// writes plaintext to the shared recordings volume at the path the backend hands it
// (recording-path / recording-name); the backend never sees those bytes as they are
// written, so it cannot stream-encrypt them mid-session.
//
// The only Go-controlled moment is when the session ends (onDisconnect): the file is
// then fully written on disk, and the backend re-writes it encrypted in place. That
// is what encryptFileAtRest does. During the live session the file is briefly
// plaintext on the (already access-controlled) volume; once the session finalizes it
// is encrypted at rest.
//
// Format. To keep a SINGLE decryption implementation across SSH and RDP, the encrypted
// file uses the exact on-disk format of internal/recorder, so recorder.Open /
// recorder.ReadFile (used by the replay + download handlers) decrypt it transparently:
//
//	magic(4) ‖ frame*        where frame = len(4, big-endian) ‖ nonce(12) ‖ ciphertext
//
// Each frame carries its own random 12-byte nonce; the plaintext is split into
// fixed-size chunks so a large recording is not sealed as one giant blob. The AES-256
// key is SHA-256(cfg.RecordingEncryptionKey), matching recorder. These constants MUST
// stay in sync with internal/recorder/crypto.go; the round-trip test
// (crypto_test.go) decrypts with recorder.ReadFile and so fails loudly if they drift.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/kforbus3/Moorgate/backend/internal/recorder"
)

// recMagic and recNonceLen mirror internal/recorder's on-disk framing so the recorder
// readers can decrypt RDP recordings.
var recMagic = []byte{0xF1, 0x33, 0x7C, 0x01}

const (
	recNonceLen  = 12
	encChunkSize = 64 * 1024 // plaintext bytes per sealed frame
)

// gcmFor derives the AES-256-GCM AEAD from an arbitrary-length key (SHA-256(key)),
// identically to internal/recorder.
func gcmFor(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, errors.New("rdp: empty encryption key")
	}
	sum := sha256.Sum256(key)
	blk, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// sealFrame encrypts one plaintext chunk into a self-framed chunk:
// len(4) ‖ nonce(12) ‖ ciphertext.
func sealFrame(gcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, recNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 4+recNonceLen+len(ct))
	binary.BigEndian.PutUint32(out[:4], uint32(len(ct)))
	copy(out[4:], nonce)
	copy(out[4+recNonceLen:], ct)
	return out, nil
}

// encryptFileAtRest re-writes the plaintext recording at path as an encrypted file in
// recorder's framed format. It is a no-op when the key is empty (legacy plaintext),
// when the file is missing (session too short for guacd to write anything), or when
// the file is already encrypted (idempotent). The rewrite goes through a temp file and
// an atomic rename so a crash never leaves a half-encrypted recording.
func encryptFileAtRest(path string, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	src, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer src.Close()

	head := make([]byte, len(recMagic))
	n, err := io.ReadFull(src, head)
	if err == io.EOF {
		return nil // empty file: nothing to encrypt
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	if recorder.IsEncrypted(head[:n]) {
		return nil // already encrypted
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}

	gcm, err := gcmFor(key)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".enc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	bw := bufio.NewWriter(tmp)
	if _, err := bw.Write(recMagic); err != nil {
		tmp.Close()
		return err
	}
	buf := make([]byte, encChunkSize)
	for {
		rn, rerr := src.Read(buf)
		if rn > 0 {
			frame, ferr := sealFrame(gcm, buf[:rn])
			if ferr != nil {
				tmp.Close()
				return ferr
			}
			if _, werr := bw.Write(frame); werr != nil {
				tmp.Close()
				return werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmp.Close()
			return rerr
		}
	}
	if err := bw.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
