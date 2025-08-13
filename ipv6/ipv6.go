// Package ipv6 provides utilities for working with IPv6 addresses and CIDR
// networks: parsing, formatting, arithmetic, subnetting, summarization and
// relationship tests.
package ipv6

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
)

// Address represents a single 128-bit IPv6 address (always a 16-byte value).
type Address struct {
	ip net.IP // 16 bytes
}

// NewAddress returns an Address from a net.IP ensuring it is a pure (non IPv4-
// mapped) IPv6 address.
func NewAddress(ip net.IP) (Address, error) {
	v := ip.To16()
	if v == nil || v.To4() != nil {
		return Address{}, errors.New("not a valid IPv6 address")
	}
	return Address{ip: append(net.IP(nil), v...)}, nil
}

// Parse converts a textual IPv6 address into an Address.
func Parse(s string) (Address, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return Address{}, fmt.Errorf("invalid IPv6 address: %s", s)
	}
	return NewAddress(ip)
}

// String returns the compressed textual representation.
func (a Address) String() string { return a.ip.String() }

// Expanded returns the fully expanded 8 * 16-bit hex block representation.
func (a Address) Expanded() string {
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%04x", int(a.ip[2*i])<<8|int(a.ip[2*i+1]))
	}
	return strings.Join(parts, ":")
}

// BigInt returns a new big.Int holding the unsigned 128-bit value.
func (a Address) BigInt() *big.Int { return new(big.Int).SetBytes(a.ip) }

// Add returns a+delta (mod 2^128).
func (a Address) Add(delta *big.Int) Address {
	mod := new(big.Int).Lsh(big.NewInt(1), 128)
	v := a.BigInt()
	v.Add(v, delta)
	v.Mod(v, mod)
	b := v.FillBytes(make([]byte, 16))
	addr, _ := NewAddress(b)
	return addr
}

// Sub returns a-delta (mod 2^128).
func (a Address) Sub(delta *big.Int) Address {
	neg := new(big.Int).Neg(delta)
	return a.Add(neg)
}

// Compare performs lexicographic comparison: -1 if a<b, 0 if equal, 1 if a>b.
func (a Address) Compare(b Address) int { return bytesCompare(a.ip, b.ip) }

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) == len(b) {
		return 0
	}
	if len(a) < len(b) {
		return -1
	}
	return 1
}

// CIDR represents an IPv6 network identified by its base address and prefix length.
type CIDR struct {
	base Address
	plen int
	mask net.IPMask
}

// ParseCIDR parses a CIDR (address/prefix) string.
func ParseCIDR(s string) (CIDR, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return CIDR{}, err
	}
	addr, err := NewAddress(ip)
	if err != nil {
		return CIDR{}, err
	}
	ones, bits := n.Mask.Size()
	if bits != 128 {
		return CIDR{}, errors.New("not an IPv6 cidr")
	}
	return CIDR{base: addr.Mask(ones), plen: ones, mask: n.Mask}, nil
}

// NewCIDR constructs a canonical CIDR from a base address and prefix length.
func NewCIDR(base Address, plen int) (CIDR, error) {
	if plen < 0 || plen > 128 {
		return CIDR{}, errors.New("invalid prefix length")
	}
	mask := net.CIDRMask(plen, 128)
	return CIDR{base: base.Mask(plen), plen: plen, mask: mask}, nil
}

// String renders network in canonical form.
func (c CIDR) String() string { return fmt.Sprintf("%s/%d", c.base.String(), c.plen) }

// Base returns the network's base address.
func (c CIDR) Base() Address { return c.base }

// PrefixLength returns the prefix length.
func (c CIDR) PrefixLength() int { return c.plen }

// Mask returns the address masked to plen bits.
func (a Address) Mask(plen int) Address {
	mask := net.CIDRMask(plen, 128)
	b := append(net.IP(nil), a.ip...)
	for i := 0; i < 16; i++ {
		b[i] &= mask[i]
	}
	addr, _ := NewAddress(b)
	return addr
}

// Network returns the base (network) address.
func (c CIDR) Network() Address { return c.base }

// HostCount returns the number of addresses in the network as a big.Int.
func (c CIDR) HostCount() *big.Int {
	bits := 128 - c.plen
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

// FirstHost returns the first address (same as the network address in IPv6).
func (c CIDR) FirstHost() Address { return c.base }

// LastHost returns the last address in the network.
func (c CIDR) LastHost() Address {
	bc := c.base.BigInt()
	cnt := c.HostCount()
	last := new(big.Int).Add(bc, cnt)
	last.Sub(last, big.NewInt(1))
	b := last.FillBytes(make([]byte, 16))
	addr, _ := NewAddress(b)
	return addr
}

// ContainsAddress reports whether a is inside c.
func (c CIDR) ContainsAddress(a Address) bool {
	return c.base.Compare(a.Mask(c.plen)) == 0
}

// ContainsCIDR reports whether network o is fully contained within c.
func (c CIDR) ContainsCIDR(o CIDR) bool {
	return c.plen <= o.plen && c.ContainsAddress(o.base)
}

// Overlaps reports whether two networks overlap in address space.
func (c CIDR) Overlaps(o CIDR) bool {
	if c.plen <= o.plen {
		return c.ContainsAddress(o.base) || o.ContainsAddress(c.LastHost())
	}
	return o.Overlaps(c)
}

// Next returns the next adjacent network of the same prefix length.
func (c CIDR) Next() CIDR {
	inc := c.HostCount()
	addr := c.base.Add(inc)
	res, _ := NewCIDR(addr, c.plen)
	return res
}

// Prev returns the previous adjacent network of the same prefix length.
func (c CIDR) Prev() CIDR {
	inc := c.HostCount()
	addr := c.base.Sub(inc)
	res, _ := NewCIDR(addr, c.plen)
	return res
}

// Split divides the network into subnets of newPrefix length.
func (c CIDR) Split(newPrefix int) ([]CIDR, error) {
	if newPrefix <= c.plen || newPrefix > 128 {
		return nil, errors.New("invalid new prefix")
	}
	countBits := newPrefix - c.plen
	parts := 1 << countBits
	res := make([]CIDR, 0, parts)
	step := new(big.Int).Rsh(c.HostCount(), uint(countBits))
	cur := c.base
	for i := 0; i < parts; i++ {
		sub, _ := NewCIDR(cur, newPrefix)
		res = append(res, sub)
		cur = cur.Add(step)
	}
	return res, nil
}

// Summarize tries to merge CIDRs into the minimal covering list by combining
// sibling networks where possible.
func Summarize(cidrs []CIDR) []CIDR {
	if len(cidrs) == 0 {
		return nil
	}
	// normalize and sort
	norm := make([]CIDR, len(cidrs))
	copy(norm, cidrs)
	for i := range norm {
		norm[i].base = norm[i].base.Mask(norm[i].plen)
	}
	sort.Slice(norm, func(i, j int) bool {
		return norm[i].base.Compare(norm[j].base) < 0 || (norm[i].base.Compare(norm[j].base) == 0 && norm[i].plen < norm[j].plen)
	})
	changed := true
	for changed {
		changed = false
		out := make([]CIDR, 0, len(norm))
		for i := 0; i < len(norm); {
			if i+1 < len(norm) && norm[i].plen == norm[i+1].plen {
				parentPrefix := norm[i].plen - 1
				if parentPrefix >= 0 {
					parent1 := norm[i].base.Mask(parentPrefix)
					parent2 := norm[i+1].base.Mask(parentPrefix)
					if parent1.Compare(parent2) == 0 && norm[i].Next().base.Compare(norm[i+1].base) == 0 {
						merged, _ := NewCIDR(parent1, parentPrefix)
						out = append(out, merged)
						changed = true
						i += 2
						continue
					}
				}
			}
			out = append(out, norm[i])
			i++
		}
		norm = out
	}
	return norm
}

// ReverseDNS returns the ip6.arpa reverse mapping domain name.
func (a Address) ReverseDNS() string {
	hexstr := hex.EncodeToString(a.ip)
	var b strings.Builder
	for i := len(hexstr) - 1; i >= 0; i-- {
		b.WriteByte(hexstr[i])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa.")
	return b.String()
}

// Offset adds an unsigned 64-bit offset (mod 2^128).
func (a Address) Offset(u uint64) Address {
	delta := new(big.Int).SetUint64(u)
	return a.Add(delta)
}

// Distance returns the unsigned distance between two addresses.
func Distance(a, b Address) *big.Int {
	ai := a.BigInt()
	bi := b.BigInt()
	if ai.Cmp(bi) > 0 {
		ai, bi = bi, ai
	}
	return new(big.Int).Sub(bi, ai)
}
