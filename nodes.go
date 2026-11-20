package koloswarm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

const (
	// maxNodes bounds the names resolved at each Bootstrap, the same cap as kolo-node's -bootstrap.
	maxNodes = 16
	// maxAddrsPerName lets one name front several entry nodes.
	maxAddrsPerName = 8
	// maxBootAddrs is kolo-dht's own cap on the servers one Bootstrap uses, so none is dropped there.
	maxBootAddrs = 64
	// maxNodeFile bounds what a wrong path can make LoadNodes read, the same bound as kolo-node's config file.
	maxNodeFile = 64 << 10
)

// resolver is the part of *net.Resolver used to resolve bootstrap node names.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ParseNodes parses a comma-separated list of at most 16 bootstrap nodes, each host:port with an IPv4 address or a host
// name and a port from 1 to 65535. Spaces around entries and empty entries are ignored and duplicates dropped; IPv6 in
// any form, port 0, more entries or anything else invalid is ErrInvalidArgument.
func ParseNodes(s string) ([]string, error) {
	return appendList(nil, s, func(i int) string { return fmt.Sprintf("bootstrap node %d", i) })
}

// LoadNodes reads a file of bootstrap nodes: one host:port per line, as in ParseNodes, where "#" starts a comment and
// blank lines are ignored. It reads only a regular file of at most 64 KiB; a bad line is ErrInvalidArgument.
func LoadNodes(path string) ([]string, error) {
	b, err := readNodeFile(path, "bootstrap node file")
	if err != nil {
		return nil, err
	}
	return parseNodeFile(b)
}

// parseNodeFile parses the content of a bootstrap node file, with an optional UTF-8 BOM and CRLF line ends.
func parseNodeFile(b []byte) ([]string, error) {
	if len(b) > maxNodeFile {
		return nil, fmt.Errorf("%w: bootstrap node file larger than %d bytes", ErrInvalidArgument, maxNodeFile)
	}
	var out []string
	var err error
	n := 0
	for line := range strings.Lines(strings.TrimPrefix(string(b), "\ufeff")) {
		n++
		line, _, _ = strings.Cut(line, "#")
		if out, err = appendList(out, line, func(int) string { return fmt.Sprintf("bootstrap node file line %d", n) }); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readNodeFile reads a regular file of at most maxNodeFile bytes; what names it in errors. It refuses anything else by
// path before opening it, so a device or FIFO is never opened, and checks the opened file again, so a file swapped in
// between is refused too.
func readNodeFile(path, what string) ([]byte, error) {
	notRegular := fmt.Errorf("%w: %s %s: not a regular file", ErrInvalidArgument, what, path)
	if st, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("koloswarm: %s: %w", what, err)
	} else if !st.Mode().IsRegular() {
		return nil, notRegular
	}
	if nodeHooks.fileChecked != nil {
		nodeHooks.fileChecked(path)
	}
	f, err := openNodeFile(path)
	if err != nil {
		return nil, fmt.Errorf("koloswarm: %s: %w", what, err)
	}
	defer f.Close()
	if nodeHooks.fileOpened != nil {
		nodeHooks.fileOpened(path)
	}
	if st, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("koloswarm: %s: %w", what, err)
	} else if !st.Mode().IsRegular() {
		return nil, notRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxNodeFile+1))
	if err != nil {
		return nil, fmt.Errorf("koloswarm: %s: %w", what, err)
	}
	return b, nil
}

// appendList appends the entries of the comma-separated list s to out; where names entry i in an error.
func appendList(out []string, s string, where func(i int) string) ([]string, error) {
	i := 0
	for e := range strings.SplitSeq(s, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		i++
		var err error
		if out, err = addNode(out, e, func() string { return where(i) }); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// checkNodes returns entries normalized and without duplicates, or ErrInvalidArgument naming the first bad entry.
func checkNodes(entries []string) ([]string, error) {
	var out []string
	var err error
	for i, e := range entries {
		if out, err = addNode(out, e, func() string { return fmt.Sprintf("bootstrap node %d", i+1) }); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// addNode appends e to out once, normalized; where names e in an error.
func addNode(out []string, e string, where func() string) ([]string, error) {
	n, err := parseNode(e)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidArgument, where(), err)
	}
	if slices.Contains(out, n) {
		return out, nil
	}
	if len(out) == maxNodes {
		return nil, fmt.Errorf("%w: more than %d bootstrap nodes", ErrInvalidArgument, maxNodes)
	}
	return append(out, n), nil
}

var errNodeIPv6 = errors.New("an IPv6 address is refused: v0.1.x is IPv4 only")

// parseNode returns s as host:port with a canonical IPv4 address or a lowercase DNS name, and a port from 1 to 65535.
func parseNode(s string) (string, error) {
	if strings.Contains(s, ",") {
		return "", errors.New("want host:port")
	}
	if strings.Count(s, ":") > 1 {
		return "", errNodeIPv6
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", errors.New("want host:port")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || strings.HasPrefix(port, "0") {
		return "", errors.New("port must be a number from 1 to 65535")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return "", errNodeIPv6
		}
		if !usable(ip) {
			return "", errors.New("the address cannot be used (unspecified, multicast or reserved)")
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if !validName(host) {
		return "", errors.New("host must be an IPv4 address or a DNS name")
	}
	return net.JoinHostPort(strings.ToLower(host), port), nil
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
)

// usable is kolo-dht's rule for a server address: a unicast IPv4 address outside 0.0.0.0/8 and 240.0.0.0/4.
func usable(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsMulticast() && !thisNetwork.Contains(ip) && !reserved.Contains(ip)
}

// validName reports whether s is a DNS name of letters, digits and hyphens with an optional final dot, whose last
// label is not all digits (RFC 1123 section 2.1), so a mistyped IPv4 address is not taken for a name.
func validName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	digits := false
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		digits = true
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				digits = false
			default:
				return false
			}
		}
	}
	return !digits
}

// Address scopes, from the narrowest, as kolo-dht defines them.
const (
	scopeInvalid = iota
	scopeLoopback
	scopeLinkLocal
	scopePrivate
	scopeCGNAT // only Connect tells carrier-grade NAT from the private ranges
	scopeGlobal
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// scopeOf is kolo-dht's scope of an address; anything usable rejects is invalid.
func scopeOf(ip netip.Addr) int {
	switch {
	case !usable(ip) || ip.IsUnspecified():
		return scopeInvalid
	case ip.IsLoopback():
		return scopeLoopback
	case ip.IsLinkLocalUnicast():
		return scopeLinkLocal
	case ip.IsPrivate(), cgnat.Contains(ip):
		return scopePrivate
	}
	return scopeGlobal
}

// reachableFrom returns kolo-dht's rule for addresses learned from others, with scopes from scope: global, or in the
// scope of local. An unspecified local address has no scope, so only global addresses pass.
func reachableFrom(local netip.Addr, scope func(netip.Addr) int) func(netip.Addr) bool {
	ls := scope(local)
	return func(ip netip.Addr) bool {
		s := scope(ip)
		return s != scopeInvalid && (s == scopeGlobal || s == ls)
	}
}

// resolveNodes returns the distinct IPv4 addresses of nodes, at most maxAddrsPerName per name and maxBootAddrs in all.
// Names are resolved in parallel, each within nodeHooks.resolveTimeout, and keep only addresses reachableFrom local, so
// a DNS answer cannot point the node at a network it was not told about. Literal addresses come first, so DNS answers
// cannot push one out of the cap.
func resolveNodes(ctx context.Context, nodes []string, local netip.Addr) ([]netip.AddrPort, error) {
	answers := make([][]netip.Addr, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		host, _, _ := net.SplitHostPort(n)
		if ip, err := netip.ParseAddr(host); err == nil {
			answers[i] = []netip.Addr{ip}
			continue
		}
		wg.Go(func() {
			rctx, cancel := context.WithTimeout(ctx, nodeHooks.resolveTimeout)
			defer cancel()
			if ips, err := nodeHooks.lookupIP.LookupNetIP(rctx, "ip4", host); err == nil {
				answers[i] = ips
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keep := reachableFrom(local, scopeOf)
	var out []netip.AddrPort
	for _, literals := range []bool{true, false} {
		for i, n := range nodes {
			host, port, _ := net.SplitHostPort(n)
			if _, err := netip.ParseAddr(host); (err == nil) != literals {
				continue
			}
			p, _ := strconv.ParseUint(port, 10, 16)
			kept := 0
			for _, ip := range answers[i] {
				ap := netip.AddrPortFrom(ip.Unmap(), uint16(p))
				if kept == maxAddrsPerName || len(out) == maxBootAddrs {
					break
				}
				if !usable(ap.Addr()) || !literals && !keep(ap.Addr()) || slices.Contains(out, ap) {
					continue
				}
				out = append(out, ap)
				kept++
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("koloswarm: no bootstrap node resolved to a usable IPv4 address: %w", kolodht.ErrNoNodes)
	}
	return out, nil
}
