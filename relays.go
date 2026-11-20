package koloswarm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ParseRelays parses a comma-separated list of at most 16 relays, each host:port@key with the key as 64 hex
// characters. Spaces and empty entries are ignored and duplicates dropped; one key with two addresses, one address
// with two keys, IPv6 in any form, port 0 or anything else invalid is ErrInvalidArgument.
func ParseRelays(s string) ([]Relay, error) {
	return appendRelays(nil, s, func(i int) string { return fmt.Sprintf("relay %d", i) })
}

// LoadRelays reads a file of relays, one host:port@key per line as in ParseRelays, where "#" starts a comment and
// blank lines are ignored. It reads only a regular file of at most 64 KiB; a bad line is ErrInvalidArgument.
func LoadRelays(path string) ([]Relay, error) {
	b, err := readNodeFile(path, "relay file")
	if err != nil {
		return nil, err
	}
	return parseRelayFile(b)
}

// parseRelayFile parses the content of a relay file, with an optional UTF-8 BOM and CRLF line ends.
func parseRelayFile(b []byte) ([]Relay, error) {
	if len(b) > maxNodeFile {
		return nil, fmt.Errorf("%w: relay file larger than %d bytes", ErrInvalidArgument, maxNodeFile)
	}
	var out []Relay
	var err error
	n := 0
	for line := range strings.Lines(strings.TrimPrefix(string(b), "\ufeff")) {
		n++
		line, _, _ = strings.Cut(line, "#")
		if out, err = appendRelays(out, line, func(int) string { return fmt.Sprintf("relay file line %d", n) }); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// appendRelays appends the entries of the comma-separated list s to out; where names entry i in an error.
func appendRelays(out []Relay, s string, where func(i int) string) ([]Relay, error) {
	i := 0
	for e := range strings.SplitSeq(s, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		i++
		r, err := parseRelay(e)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidArgument, where(i), err)
		}
		if out, err = addRelay(out, r); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidArgument, where(i), err)
		}
	}
	return out, nil
}

// parseRelay parses host:port@key.
func parseRelay(s string) (Relay, error) {
	addr, k, ok := strings.Cut(s, "@")
	if !ok {
		return Relay{}, errors.New("want host:port@key")
	}
	key, err := hex.DecodeString(k)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Relay{}, fmt.Errorf("the key must be %d hex characters", 2*ed25519.PublicKeySize)
	}
	return Relay{Addr: addr, PublicKey: key}, nil
}

// checkRelays returns entries normalized and without duplicates, or an error naming the first bad entry.
func checkRelays(entries []Relay) ([]Relay, error) {
	var out []Relay
	for i, r := range entries {
		var err error
		if out, err = addRelay(out, r); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
	}
	return out, nil
}

var errTooManyRelays = fmt.Errorf("more than %d relays", maxNodes)

// addRelay appends r to out once, normalized. One key at two addresses, or one address with two keys, names two
// relays as one, since one relay process has one key and one reservation table.
func addRelay(out []Relay, r Relay) ([]Relay, error) {
	addr, err := parseNode(r.Addr)
	if err != nil {
		return nil, err
	}
	if len(r.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the key must be %d bytes", ed25519.PublicKeySize)
	}
	for _, o := range out {
		sameKey, sameAddr := bytes.Equal(o.PublicKey, r.PublicKey), o.Addr == addr
		switch {
		case sameKey && sameAddr:
			return out, nil
		case sameKey:
			return nil, errors.New("the key of an earlier relay with another address")
		case sameAddr:
			return nil, errors.New("the address of an earlier relay with another key")
		}
	}
	if len(out) == maxNodes {
		return nil, errTooManyRelays
	}
	return append(out, Relay{Addr: addr, PublicKey: bytes.Clone(r.PublicKey)}), nil
}
