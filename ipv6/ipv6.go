// Package ipv6 provides utilities for working with IPv6 addresses and CIDR
// networks: parsing, formatting, arithmetic, subnetting, summarization and
// relationship tests.
package ipv6

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"math/rand"
	"net"
	"sort"
	"strings"
)

// Sentinel errors
var (
	ErrInvalidAddress     = errors.New("ipv6: invalid address")
	ErrInvalidCIDR        = errors.New("ipv6: invalid cidr")
	ErrInvalidPrefix      = errors.New("ipv6: invalid prefix length")
	ErrInvalidSplitPrefix = errors.New("ipv6: invalid new prefix")
	// ErrSplitExcessive indicates a requested split would produce an excessive number of subnets.
	ErrSplitExcessive = errors.New("ipv6: split produces excessive subnet count")
)

const (
	// ByteLen is the length in bytes of an IPv6 address.
	ByteLen = 16
	// BitLen is the number of bits in an IPv6 address.
	BitLen = 128
	// MaxSplitParts is an upper safety cap on the number of subnets a Split/Iterator will generate
	// to avoid pathological memory / time usage. (1<<20 ~= 1M subnets)
	MaxSplitParts = 1 << 20
)

// precomputed mask table [0..128]
var maskTable [BitLen + 1][ByteLen]byte

func init() {
	for plen := 0; plen <= BitLen; plen++ {
		for i := 0; i < ByteLen; i++ {
			b := 0
			bitsLeft := plen - i*8
			if bitsLeft >= 8 {
				b = 0xff
			} else if bitsLeft > 0 {
				b = 0xff << uint(8-bitsLeft)
			}
			maskTable[plen][i] = byte(b)
		}
	}
}

// Address represents a single 128-bit IPv6 address (always a 16-byte value).
type Address struct {
	ip net.IP // 16 bytes
}

// NewAddress returns an Address from a net.IP ensuring it is a pure (non IPv4-
// mapped) IPv6 address.
func NewAddress(ip net.IP) (Address, error) {
	v := ip.To16()
	if v == nil || v.To4() != nil {
		return Address{}, ErrInvalidAddress
	}
	return Address{ip: append(net.IP(nil), v...)}, nil
}

// Parse converts a textual IPv6 address into an Address.
func Parse(s string) (Address, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return Address{}, fmt.Errorf("%w: %s", ErrInvalidAddress, s)
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

// ExpandedUpper returns the fully expanded uppercase hexadecimal form.
func (a Address) ExpandedUpper() string { return strings.ToUpper(a.Expanded()) }

// MarshalText implements encoding.TextMarshaler.
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Address) UnmarshalText(b []byte) error {
	addr, err := Parse(string(b))
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// BigInt returns a new big.Int holding the unsigned 128-bit value.
func (a Address) BigInt() *big.Int { return new(big.Int).SetBytes(a.ip) }

// AddressFromBigInt converts a big.Int (0<=v<2^128) to Address.
func AddressFromBigInt(v *big.Int) (Address, error) {
	if v.Sign() < 0 || v.BitLen() > 128 {
		return Address{}, ErrInvalidAddress
	}
	b := v.FillBytes(make([]byte, 16))
	return NewAddress(net.IP(b))
}

// internal fast representation helpers
func (a Address) hiLo() (hi, lo uint64) {
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(a.ip[i])
	}
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(a.ip[i])
	}
	return
}
func fromHiLo(hi, lo uint64) Address {
	b := make([]byte, 16)
	for i := 7; i >= 0; i-- {
		b[i] = byte(hi)
		hi >>= 8
	}
	for i := 15; i >= 8; i-- {
		b[i] = byte(lo)
		lo >>= 8
	}
	addr, _ := NewAddress(b)
	return addr
}

// Add returns a+delta (mod 2^128). Negative deltas are treated as subtraction.
func (a Address) Add(delta *big.Int) Address {
	if delta.Sign() < 0 {
		return a.Sub(new(big.Int).Abs(delta))
	}
	// fast path for <=64-bit delta
	if delta.BitLen() <= 64 {
		hi, lo := a.hiLo()
		lo2 := lo + delta.Uint64()
		carry := uint64(0)
		if lo2 < lo {
			carry = 1
		}
		hi += carry
		return fromHiLo(hi, lo2)
	}
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
	if delta.Sign() < 0 { // subtracting a negative => addition
		return a.Add(new(big.Int).Abs(delta))
	}
	// fast path for <=64-bit delta
	if delta.BitLen() <= 64 {
		// perform subtraction in hi/lo
		hi, lo := a.hiLo()
		d := delta.Uint64()
		if lo >= d {
			lo = lo - d
		} else {
			lo = (lo - d) // wrap
			hi--
		}
		return fromHiLo(hi, lo)
	}
	// big path
	mod := new(big.Int).Lsh(big.NewInt(1), 128)
	v := a.BigInt()
	v.Sub(v, delta)
	if v.Sign() < 0 { // wrap
		v.Add(v, mod)
	}
	b := v.FillBytes(make([]byte, 16))
	addr, _ := NewAddress(b)
	return addr
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
}

// ParseCIDR parses a CIDR (address/prefix) string.
func ParseCIDR(s string) (CIDR, error) {
	// Manual split to distinguish invalid address versus invalid prefix
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 2 {
		return CIDR{}, ErrInvalidCIDR
	}
	addr, err := Parse(parts[0])
	if err != nil {
		return CIDR{}, err
	}
	plen, perr := parsePrefix(parts[1])
	if perr != nil {
		return CIDR{}, perr
	}
	return NewCIDR(addr, plen)
}

func parsePrefix(p string) (int, error) {
	if p == "" {
		return 0, ErrInvalidPrefix
	}
	// avoid strconv import here by manual parse (short string, <=3 chars)
	val := 0
	for _, r := range p {
		if r < '0' || r > '9' {
			return 0, ErrInvalidPrefix
		}
		val = val*10 + int(r-'0')
		if val > BitLen { // early stop
			return 0, ErrInvalidPrefix
		}
	}
	if val < 0 || val > BitLen {
		return 0, ErrInvalidPrefix
	}
	return val, nil
}

// NewCIDR constructs a canonical CIDR from a base address and prefix length.
func NewCIDR(base Address, plen int) (CIDR, error) {
	if plen < 0 || plen > 128 {
		return CIDR{}, ErrInvalidPrefix
	}
	return CIDR{base: base.Mask(plen), plen: plen}, nil
}

// String renders network in canonical form.
func (c CIDR) String() string { return fmt.Sprintf("%s/%d", c.base.String(), c.plen) }

// Base returns the network's base address.
func (c CIDR) Base() Address { return c.base }

// PrefixLength returns the prefix length.
func (c CIDR) PrefixLength() int { return c.plen }

// Mask returns the address masked to plen bits. Panics if plen is invalid.
func (a Address) Mask(plen int) Address {
	if plen < 0 || plen > BitLen {
		panic("ipv6: invalid prefix length in Mask")
	}
	b := append(net.IP(nil), a.ip...)
	m := maskTable[plen]
	for i := 0; i < ByteLen; i++ {
		b[i] &= m[i]
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
func (c CIDR) ContainsAddress(a Address) bool { return c.base.Compare(a.Mask(c.plen)) == 0 }

// ContainsCIDR reports whether network o is fully contained within c.
func (c CIDR) ContainsCIDR(o CIDR) bool { return c.plen <= o.plen && c.ContainsAddress(o.base) }

// Overlaps reports whether two networks overlap in address space (interval test).
func (c CIDR) Overlaps(o CIDR) bool {
	cStart := c.FirstHost().BigInt()
	cEnd := c.LastHost().BigInt()
	oStart := o.FirstHost().BigInt()
	oEnd := o.LastHost().BigInt()
	return cStart.Cmp(oEnd) <= 0 && oStart.Cmp(cEnd) <= 0
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

// Split divides the network into subnets of newPrefix length. Allows newPrefix == c.plen (returns self).
func (c CIDR) Split(newPrefix int) ([]CIDR, error) {
	if newPrefix < c.plen || newPrefix > 128 {
		return nil, ErrInvalidSplitPrefix
	}
	if newPrefix == c.plen { // degenerate split: single subnet
		return []CIDR{c}, nil
	}
	countBits := newPrefix - c.plen
	if countBits >= 63 { // guard shift overflow / unrealistic allocation
		return nil, ErrSplitExcessive
	}
	parts := uint64(1) << uint(countBits)
	if parts > MaxSplitParts { // safety cap
		return nil, ErrSplitExcessive
	}
	res := make([]CIDR, 0, parts)
	step := new(big.Int).Rsh(c.HostCount(), uint(countBits))
	cur := c.base
	for i := uint64(0); i < parts; i++ {
		sub, _ := NewCIDR(cur, newPrefix)
		res = append(res, sub)
		cur = cur.Add(step)
	}
	return res, nil
}

// SubnetIterator allows streaming iteration over subnets without allocating all.
type SubnetIterator struct {
	remaining int
	current   Address
	step      *big.Int
	plen      int
}

// SubnetIterator returns an iterator for subnets at newPrefix. Allows equality (single subnet iteration).
func (c CIDR) SubnetIterator(newPrefix int) (*SubnetIterator, error) {
	if newPrefix < c.plen || newPrefix > 128 {
		return nil, ErrInvalidSplitPrefix
	}
	if newPrefix == c.plen {
		return &SubnetIterator{remaining: 1, current: c.base, step: new(big.Int), plen: newPrefix}, nil
	}
	countBits := newPrefix - c.plen
	if countBits >= 63 {
		return nil, ErrSplitExcessive
	}
	parts := uint64(1) << uint(countBits)
	if parts > MaxSplitParts {
		return nil, ErrSplitExcessive
	}
	step := new(big.Int).Rsh(c.HostCount(), uint(countBits))
	return &SubnetIterator{remaining: int(parts), current: c.base, step: step, plen: newPrefix}, nil
}

// Next returns next subnet and true, or zero value and false when done.
func (it *SubnetIterator) Next() (CIDR, bool) {
	if it.remaining == 0 {
		return CIDR{}, false
	}
	c, _ := NewCIDR(it.current, it.plen)
	it.current = it.current.Add(it.step)
	it.remaining--
	return c, true
}

// Summarize tries to merge CIDRs into the minimal covering list by combining
// sibling networks where possible.
func Summarize(cidrs []CIDR) []CIDR {
	if len(cidrs) == 0 {
		return nil
	}
	// normalize & sort by base then prefix length (shorter first)
	norm := make([]CIDR, len(cidrs))
	copy(norm, cidrs)
	for i := range norm {
		norm[i].base = norm[i].base.Mask(norm[i].plen)
	}
	sort.Slice(norm, func(i, j int) bool {
		cmp := norm[i].base.Compare(norm[j].base)
		if cmp == 0 {
			return norm[i].plen < norm[j].plen
		}
		return cmp < 0
	})
	stack := make([]CIDR, 0, len(norm))
	for _, c := range norm {
		// skip if contained in previous summarized CIDR
		if l := len(stack); l > 0 && stack[l-1].ContainsCIDR(c) {
			continue
		}
		stack = append(stack, c)
		// attempt upward merges greedily
		for len(stack) >= 2 {
			last := stack[len(stack)-1]
			prev := stack[len(stack)-2]
			if last.plen != prev.plen {
				break
			}
			if last.plen == 0 { // cannot merge further
				break
			}
			if prev.Next().base.Compare(last.base) != 0 { // not adjacent siblings
				break
			}
			parentPrefix := last.plen - 1
			parentBase := prev.base.Mask(parentPrefix)
			// ensure alignment
			if parentBase.Compare(last.base.Mask(parentPrefix)) != 0 {
				break
			}
			// merge
			stack = stack[:len(stack)-2]
			parent, _ := NewCIDR(parentBase, parentPrefix)
			stack = append(stack, parent)
		}
	}
	return stack
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
	ahi, alo := a.hiLo()
	bhi, blo := b.hiLo()
	// ensure a <= b
	if ahi > bhi || (ahi == bhi && alo > blo) {
		ahi, alo, bhi, blo = bhi, blo, ahi, alo
	}
	var dhi, dlo uint64
	if blo >= alo {
		dlo = blo - alo
		dhi = bhi - ahi
	} else { // borrow from high word
		dlo = (blo - alo) // underflow wraps, equivalent to 2^64 + blo - alo
		dhi = (bhi - 1) - ahi
	}
	buf := make([]byte, 16)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(dhi)
		dhi >>= 8
	}
	for i := 15; i >= 8; i-- {
		buf[i] = byte(dlo)
		dlo >>= 8
	}
	return new(big.Int).SetBytes(buf)
}

// CoverRange returns the minimal set of CIDRs covering the inclusive address range [start,end].
func CoverRange(start, end Address) ([]CIDR, error) {
	if start.Compare(end) > 0 {
		return nil, errors.New("ipv6: invalid range")
	}
	var res []CIDR
	cur := start
	one := big.NewInt(1)
	for cur.Compare(end) <= 0 {
		rem := new(big.Int).Add(Distance(cur, end), one) // remaining count
		// count trailing zero bits of current address
		hi, lo := cur.hiLo()
		var tz int
		if lo != 0 {
			tz = bits.TrailingZeros64(lo)
		} else if hi != 0 {
			tz = 64 + bits.TrailingZeros64(hi)
		} else {
			tz = 128
		}
		// largest exponent allowed by remaining size
		remBits := rem.BitLen() - 1 // floor(log2(rem))
		if remBits < 0 {
			remBits = 0
		}
		if tz > remBits {
			tz = remBits
		}
		prefix := 128 - tz
		cid, _ := NewCIDR(cur, prefix)
		res = append(res, cid)
		cur = cid.LastHost().Add(one)
	}
	return res, nil
}

// Supernet returns the smallest CIDR containing all provided CIDRs.
func Supernet(list []CIDR) (CIDR, error) {
	if len(list) == 0 {
		return CIDR{}, errors.New("ipv6: empty list")
	}
	min := list[0].FirstHost()
	max := list[0].LastHost()
	for _, c := range list[1:] {
		if c.FirstHost().Compare(min) < 0 {
			min = c.FirstHost()
		}
		if c.LastHost().Compare(max) > 0 {
			max = c.LastHost()
		}
	}
	// find common prefix bits of min & max
	mb := min.ip
	xb := max.ip
	prefix := 0
	for i := 0; i < 16; i++ {
		if mb[i] == xb[i] {
			prefix += 8
			continue
		}
		// differ within this byte
		for b := 7; b >= 0; b-- {
			mask := byte(1 << uint(b))
			if (mb[i] & mask) == (xb[i] & mask) {
				prefix++
			} else {
				break
			}
		}
		break
	}
	return NewCIDR(min.Mask(prefix), prefix)
}

// Random utilities

// RandomAddressInCIDR returns a uniform random address inside CIDR using rand source.
func RandomAddressInCIDR(c CIDR, r *rand.Rand) Address {
	// generate offset in host portion bits
	bits := 128 - c.plen
	if bits == 0 {
		return c.base
	}
	// produce up to bits random bits as big.Int
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	offset := new(big.Int).Rand(r, max)
	addr := c.base.Add(offset)
	return addr
}

// RandomSubnetInCIDR returns a random subnet of newPrefix inside c.
func RandomSubnetInCIDR(c CIDR, newPrefix int, r *rand.Rand) (CIDR, error) {
	if newPrefix < c.plen || newPrefix > 128 {
		return CIDR{}, ErrInvalidSplitPrefix
	}
	if newPrefix == c.plen {
		return c, nil
	}
	countBits := newPrefix - c.plen
	parts := new(big.Int).Lsh(big.NewInt(1), uint(countBits))
	idx := new(big.Int).Rand(r, parts)
	step := new(big.Int).Rsh(c.HostCount(), uint(countBits))
	base := c.base.Add(new(big.Int).Mul(idx, step))
	return NewCIDR(base, newPrefix)
}

// ExampleParse demonstrates parsing an IPv6 address.
func ExampleParse() {
	addr, _ := Parse("2001:db8::1")
	fmt.Println(addr.String())
	// Output: 2001:db8::1
}

// ExampleParseCIDR shows parsing a CIDR and getting first/last hosts.
func ExampleParseCIDR() {
	c, _ := ParseCIDR("2001:db8::/126")
	fmt.Println(c.FirstHost(), c.LastHost())
	// Output: 2001:db8:: 2001:db8::3
}

// ExampleSummarize merges sibling CIDRs.
func ExampleSummarize() {
	c1, _ := ParseCIDR("2001:db8::/65")
	c2 := c1.Next()
	res := Summarize([]CIDR{c1, c2})
	for _, r := range res {
		fmt.Println(r)
	}
	// Output: 2001:db8::/64
}

// ExampleCoverRange demonstrates covering a range with minimal CIDRs.
func ExampleCoverRange() {
	a, _ := Parse("2001:db8::1")
	b, _ := Parse("2001:db8::ff")
	cover, _ := CoverRange(a, b)
	fmt.Println(len(cover))
	// Output: 8
}

// ExampleSupernet shows computing the smallest CIDR containing others.
func ExampleSupernet() {
	c1, _ := ParseCIDR("2001:db8::/65")
	c2 := c1.Next()
	s, _ := Supernet([]CIDR{c1, c2})
	fmt.Println(s)
	// Output: 2001:db8::/64
}

// ExampleAddress_Expanded demonstrates uppercase expansion.
func ExampleAddress_Expanded() {
	addr, _ := Parse("2001:db8::1")
	fmt.Println(addr.ExpandedUpper())
	// Output: 2001:0DB8:0000:0000:0000:0000:0000:0001
}

// ExampleNewAddress demonstrates constructing an Address from net.IP.
func ExampleNewAddress() {
	ip := net.ParseIP("2001:db8::1")
	addr, _ := NewAddress(ip)
	fmt.Println(addr)
	// Output: 2001:db8::1
}

// ExampleNewCIDR demonstrates constructing a CIDR explicitly.
func ExampleNewCIDR() {
	addr, _ := Parse("2001:db8::1")
	c, _ := NewCIDR(addr, 64)
	fmt.Println(c)
	// Output: 2001:db8::/64
}

// ExampleAddress_Mask shows masking an address to a prefix length.
func ExampleAddress_Mask() {
	addr, _ := Parse("2001:db8::1")
	fmt.Println(addr.Mask(64))
	// Output: 2001:db8::
}

// ExampleCIDR_Split demonstrates splitting a small network.
func ExampleCIDR_Split() {
	c, _ := ParseCIDR("2001:db8::/126")
	subs, _ := c.Split(127)
	for _, s := range subs {
		fmt.Println(s)
	}
	// Output:
	// 2001:db8::/127
	// 2001:db8::2/127
}

// ExampleCIDR_SubnetIterator demonstrates streaming subnets.
func ExampleCIDR_SubnetIterator() {
	c, _ := ParseCIDR("2001:db8::/126")
	it, _ := c.SubnetIterator(127)
	for {
		s, ok := it.Next()
		if !ok {
			break
		}
		fmt.Println(s)
	}
	// Output:
	// 2001:db8::/127
	// 2001:db8::2/127
}

// ExampleCIDR_NextPrev shows adjacent network navigation.
func ExampleCIDR_NextPrev() {
	c, _ := ParseCIDR("2001:db8::/64")
	fmt.Println(c.Next())
	fmt.Println(c.Next().Prev())
	// Output:
	// 2001:db8:0:1::/64
	// 2001:db8::/64
}

// ExampleCIDR_ContainsAddress shows containment test.
func ExampleCIDR_ContainsAddress() {
	c, _ := ParseCIDR("2001:db8::/64")
	a, _ := Parse("2001:db8::1")
	b, _ := Parse("2001:db8:0:1::1")
	fmt.Println(c.ContainsAddress(a))
	fmt.Println(c.ContainsAddress(b))
	// Output:
	// true
	// false
}

// ExampleDistance shows distance between two addresses.
func ExampleDistance() {
	a, _ := Parse("2001:db8::1")
	b, _ := Parse("2001:db8::5")
	fmt.Println(Distance(a, b))
	// Output: 4
}

// ExampleAddress_ReverseDNS shows reverse DNS form.
func ExampleAddress_ReverseDNS() {
	addr, _ := Parse("2001:db8::1")
	fmt.Println(addr.ReverseDNS())
	// Output: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
}

// ExampleAddressFromBigInt demonstrates constructing from integer.
func ExampleAddressFromBigInt() {
	addr, _ := AddressFromBigInt(big.NewInt(1))
	fmt.Println(addr)
	// Output: ::1
}

// ExampleRandomAddressInCIDR uses a /128 for deterministic output.
func ExampleRandomAddressInCIDR() {
	c, _ := ParseCIDR("2001:db8::1/128")
	r := rand.New(rand.NewSource(1))
	fmt.Println(RandomAddressInCIDR(c, r))
	// Output: 2001:db8::1
}

// ExampleRandomSubnetInCIDR uses equal newPrefix for deterministic output.
func ExampleRandomSubnetInCIDR() {
	c, _ := ParseCIDR("2001:db8::/64")
	r := rand.New(rand.NewSource(1))
	s, _ := RandomSubnetInCIDR(c, 64, r)
	fmt.Println(s)
	// Output: 2001:db8::/64
}
