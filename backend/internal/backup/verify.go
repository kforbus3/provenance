package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// A backup nobody has ever read is a hope, not a backup.
//
// This deployment took a pre-upgrade dump before every upgrade and refused to proceed
// without one — and there was no code anywhere that could read one back. The files
// were created, listed, downloaded, and never opened. The comment beside the HMAC even
// said the tag is "verified before a restore", describing an arrangement that did not
// exist, because there was no restore.
//
// So: Verify reads the whole file the way a restore would, and says what it found. It
// touches no database and holds no lock, which is what makes it safe to run on a
// schedule — the point being to learn that a backup is unreadable on an ordinary
// Tuesday rather than during an incident.

// VerifyResult is what reading a backup end to end established.
type VerifyResult struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// HMACPresent is false for backups written before the sidecar existed, or where
	// writing it failed (which Create tolerates). Absence is not corruption, and is
	// reported separately so it cannot be read as one.
	HMACPresent bool `json:"hmacPresent"`
	HMACValid   bool `json:"hmacValid"`
	// Decrypted is the plaintext size. A backup that decrypts to nothing is the
	// failure this is most likely to catch: a wrong passphrase yields an error, but a
	// dump that was empty at creation yields a perfectly valid, perfectly useless file.
	Decrypted int64 `json:"decryptedBytes"`
	// Tables and Copies are what the dump will actually recreate.
	Tables int `json:"tables"`
	Copies int `json:"copyStatements"`
	// Complete is pg_dump's own end marker. Its absence means the dump was truncated
	// — the process died partway — and that is invisible from the file size alone.
	Complete bool          `json:"complete"`
	Took     time.Duration `json:"-"`
}

// OK reports whether this backup is one a restore could use.
func (v VerifyResult) OK() bool {
	return v.Complete && v.Tables > 0 && v.Decrypted > 0 && (!v.HMACPresent || v.HMACValid)
}

// Problem describes what is wrong, most serious first, or "" when nothing is.
func (v VerifyResult) Problem() string {
	switch {
	case v.HMACPresent && !v.HMACValid:
		return "the authentication tag does not match: this file has been altered or corrupted since it was written"
	case v.Decrypted == 0:
		return "the backup decrypts to nothing"
	case !v.Complete:
		return "the dump has no completion marker, so pg_dump did not finish writing it — it is truncated"
	case v.Tables == 0:
		return "the backup contains no table definitions"
	case !v.HMACPresent:
		return "" // not a fault; reported in the result
	}
	return ""
}

// Verify decrypts a stored backup and reads it, without writing anything.
func (s *Service) Verify(ctx context.Context, name string) (*VerifyResult, error) {
	path, err := s.Path(name)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("no such backup: %w", err)
	}
	pass := s.passphrase()
	if pass == "" {
		return nil, errors.New("no backup passphrase configured, so this backup cannot be read")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return nil, errors.New("openssl not available")
	}
	started := time.Now()
	res := &VerifyResult{Name: name, Size: fi.Size()}

	// The tag first, over the ciphertext, exactly as Create computed it.
	if tag, err := os.ReadFile(path + hmacSuffix); err == nil {
		res.HMACPresent = true
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil, ferr
		}
		mac := hmac.New(sha256.New, backupHMACKey(pass))
		_, cerr := io.Copy(mac, f)
		f.Close()
		if cerr != nil {
			return nil, cerr
		}
		want := strings.TrimSpace(string(tag))
		res.HMACValid = hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(want))
		// A tampered file is not decrypted. Feeding unauthenticated ciphertext to a
		// decryptor is the thing the tag exists to prevent.
		if !res.HMACValid {
			res.Took = time.Since(started)
			return res, nil
		}
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	dec := exec.CommandContext(cctx, "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
		"-pass", "env:PROV_BK_PASS", "-in", path)
	dec.Env = append(os.Environ(), "PROV_BK_PASS="+pass)
	out, err := dec.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var decErr strings.Builder
	dec.Stderr = &decErr
	if err := dec.Start(); err != nil {
		return nil, err
	}
	res.Decrypted, res.Tables, res.Copies, res.Complete = scanDump(out)
	if werr := dec.Wait(); werr != nil {
		return nil, fmt.Errorf("could not decrypt this backup (wrong passphrase, or the file is damaged): %v %s",
			werr, strings.TrimSpace(decErr.String()))
	}
	res.Took = time.Since(started)
	return res, nil
}

// scanDump reads a plaintext pg_dump stream and reports what is in it.
//
// Streamed rather than buffered: a real backup is hundreds of megabytes and the whole
// point is to read it on a schedule, on the machine that is also serving.
func scanDump(r io.Reader) (bytes int64, tables, copies int, complete bool) {
	buf := make([]byte, 64*1024)
	var carry string
	for {
		n, err := r.Read(buf)
		if n > 0 {
			bytes += int64(n)
			chunk := carry + string(buf[:n])
			lines := strings.Split(chunk, "\n")
			// The last piece may be a partial line; carry it to the next read so a
			// marker split across a buffer boundary is still seen.
			carry = lines[len(lines)-1]
			for _, line := range lines[:len(lines)-1] {
				switch {
				case strings.HasPrefix(line, "CREATE TABLE "):
					tables++
				case strings.HasPrefix(line, "COPY "):
					copies++
				case strings.Contains(line, "PostgreSQL database dump complete"):
					complete = true
				}
			}
		}
		if err != nil {
			// Whatever is left in carry is a final line with no newline.
			switch {
			case strings.HasPrefix(carry, "CREATE TABLE "):
				tables++
			case strings.Contains(carry, "PostgreSQL database dump complete"):
				complete = true
			}
			return bytes, tables, copies, complete
		}
	}
}
