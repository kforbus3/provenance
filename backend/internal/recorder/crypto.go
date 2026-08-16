package recorder

// Recording-at-rest encryption.
//
// Session recordings can contain everything typed and printed in a shell — secrets,
// tokens, PII — so when cfg.RecordingEncryptionKey is set they are encrypted on disk
// with AES-256-GCM. When the key is empty the recorder writes legacy plaintext
// asciicast (unchanged), and the readers below pass such files through untouched, so
// enabling the key is transparent for existing recordings.
//
// Format. An encrypted recording is a magic prefix followed by a sequence of framed
// GCM chunks, one per asciicast line:
//
//	magic(4) ‖ frame*         where frame = len(4, big-endian) ‖ nonce(12) ‖ ciphertext(len)
//
// Each frame carries its OWN random 12-byte nonce. This is deliberately stronger than
// a single per-file nonce: a recording is written incrementally as the session runs
// and appended to live, which a single whole-file GCM seal cannot do (it would have to
// buffer the whole session and could not survive a crash mid-session). Per-chunk
// framing keeps every completed line durably encrypted on disk, and a truncated
// trailing frame (crash) is simply dropped on read. secretbox's whole-blob Seal is
// reused for small at-rest secrets but is unsuitable here for the same streaming
// reason, so this package carries its own framing.
//
// Key. cfg.RecordingEncryptionKey may be any length; the 32-byte AES-256 key is
// SHA-256(key). Nonces are random per frame, so a fixed key is safe for the message
// volumes a recording produces.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// recMagic marks an encrypted recording file. A legacy plaintext asciicast starts
// with '{' (the JSON header), so the two are unambiguous.
var recMagic = []byte{0xF1, 0x33, 0x7C, 0x01}

const recNonceLen = 12

// recGCM derives the AES-256-GCM AEAD from an arbitrary-length key.
func recGCM(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, errors.New("recorder: empty encryption key")
	}
	sum := sha256.Sum256(key)
	blk, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// sealFrame encrypts one plaintext line into a self-framed chunk:
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

// IsEncrypted reports whether a recording file's leading bytes are the encrypted
// magic (as opposed to legacy plaintext asciicast).
func IsEncrypted(head []byte) bool { return bytes.HasPrefix(head, recMagic) }

// ReadFile reads a recording, transparently decrypting it when it is encrypted and
// a key is supplied. A legacy plaintext file is returned as-is (the key is ignored),
// so callers can pass cfg.RecordingEncryptionKey unconditionally. Decrypting an
// encrypted file with the wrong/empty key returns an error rather than garbage.
func ReadFile(path string, key []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !IsEncrypted(raw) {
		return raw, nil
	}
	gcm, err := recGCM(key)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	body := raw[len(recMagic):]
	for len(body) >= 4+recNonceLen {
		n := int(binary.BigEndian.Uint32(body[:4]))
		if len(body) < 4+recNonceLen+n {
			break // truncated trailing frame (crash): stop cleanly
		}
		nonce := body[4 : 4+recNonceLen]
		ct := body[4+recNonceLen : 4+recNonceLen+n]
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, err
		}
		out.Write(pt)
		body = body[4+recNonceLen+n:]
	}
	return out.Bytes(), nil
}

// Open returns a reader over a recording's plaintext, transparently decrypting an
// encrypted file frame-by-frame (so large recordings need not be buffered whole) and
// passing a legacy plaintext file straight through. Callers must Close the result.
func Open(path string, key []byte) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head, err := readHead(f, len(recMagic))
	if err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if !IsEncrypted(head) {
		return f, nil // legacy plaintext
	}
	gcm, err := recGCM(key)
	if err != nil {
		f.Close()
		return nil, err
	}
	br := bufio.NewReader(f)
	if _, err := br.Discard(len(recMagic)); err != nil {
		f.Close()
		return nil, err
	}
	return &frameReader{f: f, br: br, gcm: gcm}, nil
}

func readHead(f *os.File, n int) ([]byte, error) {
	head := make([]byte, n)
	got, err := io.ReadFull(f, head)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return head[:got], nil // shorter than a magic: definitely not encrypted
	}
	if err != nil {
		return nil, err
	}
	return head, nil
}

// frameReader decrypts a framed recording on the fly.
type frameReader struct {
	f   *os.File
	br  *bufio.Reader
	gcm cipher.AEAD
	buf bytes.Buffer
	eof bool
}

func (r *frameReader) Read(p []byte) (int, error) {
	for r.buf.Len() == 0 && !r.eof {
		if err := r.next(); err != nil {
			if err == io.EOF {
				r.eof = true
				break
			}
			return 0, err
		}
	}
	if r.buf.Len() == 0 {
		return 0, io.EOF
	}
	return r.buf.Read(p)
}

// next reads and decrypts one frame into the buffer. A truncated trailing frame is
// treated as a clean EOF (a session that crashed mid-write).
func (r *frameReader) next() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r.br, lenBuf[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return io.EOF
		}
		return err
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	frame := make([]byte, recNonceLen+n)
	if _, err := io.ReadFull(r.br, frame); err != nil {
		if err == io.ErrUnexpectedEOF {
			return io.EOF
		}
		return err
	}
	pt, err := r.gcm.Open(nil, frame[:recNonceLen], frame[recNonceLen:], nil)
	if err != nil {
		return err
	}
	r.buf.Write(pt)
	return nil
}

func (r *frameReader) Close() error { return r.f.Close() }
