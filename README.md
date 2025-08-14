# ip6calc

IPv6 subnet calculator and Go library. Provides fast, well‑tested primitives for IPv6 address parsing, formatting, arithmetic, subnetting, summarization and range coverage, plus an ergonomic CLI.

[![CI](https://github.com/zlobste/ip6calc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zlobste/ip6calc/actions/workflows/ci.yml?query=branch%3Amain)

## Install
```
go install github.com/zlobste/ip6calc/cmd/ip6calc@latest
```
Library import path:
```
import "github.com/zlobste/ip6calc/ipv6"
```

## Quick CLI Usage
```
ip6calc <command> [args] [-o human|json|yaml]
```
Common commands: `info`, `expand`, `compress`, `split`, `summarize`, `range`, `supernet`, `enumerate`, `random address`, `random subnet`, `diff`, `reverse`, `to-int`, `from-int`, `completion`, `docs`.

### CLI Examples
```bash
# Network info
ip6calc info 2001:db8::/64

# Expand / compress
ip6calc expand 2001:db8::1
ip6calc compress 2001:0db8:0000:0000:0000:0000:0000:0001

# Split / summarize
ip6calc split 2001:db8::/48 --new-prefix 52
ip6calc summarize 2001:db8::/65 2001:db8:0:0:8000::/65

# Cover range, supernet
ip6calc range 2001:db8::1-2001:db8::ff
ip6calc supernet 2001:db8::/65 2001:db8:0:0:8000::/65

# Enumerate & random
ip6calc enumerate 2001:db8::/64 --limit 5 --stride 32
ip6calc random address 2001:db8::/64 --count 3

# Diff & reverse DNS
ip6calc diff 2001:db8::/65 2001:db8::/64
ip6calc reverse 2001:db8::1 --zone

# Integer conversion
ip6calc to-int 2001:db8::1 | ip6calc from-int

# JSON output (or set IP6CALC_FORMAT)
ip6calc -o json info 2001:db8::/64
```

## Full CLI Reference
See the generated per-command Markdown docs in [docs/cli/](docs/cli/). For example: [ip6calc split](docs/cli/ip6calc_split.md), [ip6calc summarize](docs/cli/ip6calc_summarize.md), etc.

Regenerate them after changing commands:
```
ip6calc docs docs/cli
```

## Library Usage
```go
package main

import (
	"fmt"
	"math/big"

	"github.com/zlobste/ip6calc/ipv6"
)

func main() {
	// Parse address & CIDR
	addr, err := ipv6.Parse("2001:db8::1")
	if err != nil { panic(err) }
	cidr, err := ipv6.ParseCIDR("2001:db8::/64")
	if err != nil { panic(err) }

	fmt.Println("Compressed:", addr)                // 2001:db8::1
	fmt.Println("Expanded:", addr.Expanded())       // 2001:0db8:...
	fmt.Println("Host count:", cidr.HostCount())
	fmt.Println("First/Last:", cidr.FirstHost(), cidr.LastHost())

	// Arithmetic
	plus10 := addr.Add(big.NewInt(10))
	fmt.Println("+10:", plus10)
	fmt.Println("Distance:", ipv6.Distance(addr, plus10))

	// Split
	subs, _ := cidr.Split(68) // slice of sub-CIDRs
	fmt.Println("First subnet:", subs[0])

	// Summarize
	merged := ipv6.Summarize([]ipv6.CIDR{subs[0], subs[1]})
	fmt.Println("Summarized count:", len(merged))

	// Cover range with minimal CIDRs
	start, _ := ipv6.Parse("2001:db8::1")
	end, _ := ipv6.Parse("2001:db8::ff")
	cover, _ := ipv6.CoverRange(start, end)
	fmt.Println("Range blocks:", len(cover))

	// Supernet
	sn, _ := ipv6.Supernet([]ipv6.CIDR{subs[0], subs[1]})
	fmt.Println("Supernet:", sn)
}
```
(Always check returned errors in production code.)

### Key Types & Functions
- `Address` (methods: `String()`, `Expanded()`, `ExpandedUpper()`, `Add()`, `Sub()`, `BigInt()`, `Mask()`, `ReverseDNS()`).
- `CIDR` (methods: `Base()`, `PrefixLength()`, `HostCount()`, `FirstHost()`, `LastHost()`, `Split()`, `SubnetIterator()`, `ContainsAddress()`, `ContainsCIDR()`, `Overlaps()`, `Next()`, `Prev()`).
- Helpers: `Parse`, `ParseCIDR`, `Summarize`, `CoverRange`, `Supernet`, `Distance`, `RandomAddressInCIDR`, `RandomSubnetInCIDR`, `AddressFromBigInt`.

## Feature Summary
- Robust IPv6 parsing & validation (distinct sentinel errors).
- Lossless expand / compress and uppercase expansion.
- Network metrics: host counts (raw, power-of-two notation, approximate).
- Fast arithmetic (dual uint64 fast paths; big.Int fallback).
- Splitting with iterator & safeguards (`--force` for very large splits; thresholds overridable by env vars `IP6CALC_SPLIT_WARN_THRESHOLD`, `IP6CALC_SPLIT_FORCE_THRESHOLD`).
- Summarization (greedy merge of sibling CIDRs) & supernet calculation.
- Minimal CIDR cover for arbitrary address ranges.
- Enumeration (limit/stride) & random sampling (non‑cryptographic `math/rand`).
- Overlap / containment / diff analysis and reverse DNS generation.
- Integer ↔ IPv6 conversions; structured JSON/YAML schema wrapper: `{"schema":"ip6calc/v1","data":...}`.
- TTY‑friendly human output: optional color (`--color`), tables (`--table`), quiet (`--quiet`), header suppression (`--no-header`), uppercase (`--upper`).

## Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Invalid input (address/prefix) |
| 3 | Overlap detected (with `--fail-on-overlap`) |
| 4 | Split too large without `--force` |

## Environment Variables
- `IP6CALC_FORMAT` sets default output format.
- `IP6CALC_SPLIT_WARN_THRESHOLD` / `IP6CALC_SPLIT_FORCE_THRESHOLD` adjust split safeguards.

## Testing & Benchmarks
```
go test ./... -cover
# Fuzz (example)
go test -fuzz=FuzzParse -run=^$ ./ipv6
# Benchmarks
go test -bench=. ./ipv6
```
Core logic targets >90% coverage (property-based + fuzz tests included).

## Security Notes
- Input validation avoids panics; big integer bounds (<2^128) enforced.
- Random address/subnet functions are NOT cryptographically secure.
- Report vulnerabilities privately (see SECURITY.md).

## Contributing
1. Open an issue for major changes.
2. `go fmt`, `go vet`, lint (`golangci-lint run`) before PR.
3. Include tests (unit + fuzz where beneficial).
4. Keep PRs focused; maintain >90% coverage for core paths.

## License
MIT (see `LICENSE`).

---
If this project helps you, a GitHub star is appreciated.
