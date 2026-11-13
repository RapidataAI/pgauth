package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxAuthMessage caps a message read before authentication completes, on both sides of pgauth.
const maxAuthMessage = 64 << 10

// scramGuard sits between an upstream connection and pgconn's frontend until AuthenticationOk and
// refuses every method but SCRAM-SHA-256 before pgconn could answer it, so a server pretending to
// be the instance never receives a cleartext or MD5 password.
type scramGuard struct {
	r        io.Reader
	buf, out []byte
	done     bool
	err      error
}

var errAuthMethod = errors.New("upstream asked for a password method other than SCRAM-SHA-256; refused (requireScram)")

func (g *scramGuard) Read(p []byte) (int, error) {
	for len(g.out) == 0 {
		if g.err != nil {
			return 0, g.err
		}
		if g.done {
			if len(g.buf) > 0 {
				g.out, g.buf = g.buf, nil
				break
			}
			return g.r.Read(p)
		}
		if len(g.buf) >= 5 {
			size := int(binary.BigEndian.Uint32(g.buf[1:5])) + 1
			if size < 5 || size > maxAuthMessage {
				g.err = fmt.Errorf("upstream sent a %d byte message before authentication", size)
				continue
			}
			if len(g.buf) >= size {
				msg := g.buf[:size]
				if err := g.check(msg); err != nil {
					g.err = err
					continue
				}
				g.out = append(g.out, msg...)
				g.buf = g.buf[size:]
				continue
			}
		}
		tmp := make([]byte, 4096)
		n, err := g.r.Read(tmp)
		g.buf = append(g.buf, tmp[:n]...)
		if err != nil && n == 0 {
			g.err = err
		}
	}
	n := copy(p, g.out)
	g.out = g.out[n:]
	return n, nil
}

func (g *scramGuard) check(msg []byte) error {
	if msg[0] != 'R' || len(msg) < 9 {
		return nil
	}
	switch binary.BigEndian.Uint32(msg[5:9]) {
	case 0: // AuthenticationOk
		g.done = true
		return nil
	case 10: // AuthenticationSASL: the mechanism list must offer SCRAM-SHA-256
		for _, m := range strings.Split(string(msg[9:]), "\x00") {
			if m == "SCRAM-SHA-256" {
				return nil
			}
		}
		return errAuthMethod
	case 11, 12: // SASLContinue, SASLFinal
		return nil
	default:
		return errAuthMethod
	}
}
