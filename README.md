# ip6calc

IPv6 subnet calculator and Go library. Command line tool plus package for parsing, formatting, subnet math, summarization and basic analysis of IPv6 networks.

## Features
- Parse / validate IPv6 addresses and CIDRs
- Expand / compress addresses
- Network base, first, last, count of addresses
- Address arithmetic (add / subtract / offset) (library)
- Adjacent network navigation (next / prev) (library)
- Split a network into smaller subnets
- Summarize sibling networks
- Containment and overlap checks (library)
- Reverse DNS (ip6.arpa) name generation
- Output: human, JSON, YAML
- Property based tests for address round‑trip

## Install
CLI:
```
go install github.com/zlobste/ip6calc/cmd/ip6calc@latest
```
The binary is placed in $GOBIN (or $GOPATH/bin if GOBIN is unset). Ensure that directory is on PATH.

Library: import the package and Go will add the module automatically.
```
import "github.com/zlobste/ip6calc/ipv6"
```

## CLI
Usage:
```
ip6calc <command> [args] [-o human|json|yaml]
```
Commands:
- info        show details for an address or CIDR
- expand      expanded form of an address
- compress    compressed form
- split       split a CIDR into smaller prefixes
- summarize   merge a set of CIDRs
- reverse     ip6.arpa reverse DNS name

Examples:
```
# Network info
ip6calc info 2001:db8::/64

# Address info
ip6calc info 2001:db8::1

# Expand / compress
ip6calc expand 2001:db8::1
ip6calc compress 2001:0db8:0000:0000:0000:0000:0000:0001

# Split /48 into /52
ip6calc split 2001:db8::/48 --new-prefix 52

# Summarize siblings
ip6calc summarize 2001:db8::/52 2001:db8:0:1000::/52 2001:db8:0:2000::/52 2001:db8:0:3000::/52

# Reverse DNS
ip6calc reverse 2001:db8::1

# JSON output
ip6calc info 2001:db8::/64 -o json
```

## Library
Basic inspection:
```go
cidr, _ := ipv6.ParseCIDR("2001:db8::/64")
fmt.Println(cidr.Network())
fmt.Println(cidr.FirstHost())
fmt.Println(cidr.LastHost())
fmt.Println(cidr.HostCount())
```
Summarize:
```go
c1, _ := ipv6.ParseCIDR("2001:db8::/65")
c2 := c1.Next()
fmt.Println(ipv6.Summarize([]ipv6.CIDR{c1, c2})) // [2001:db8::/64]
```
Distance:
```go
a1, _ := ipv6.Parse("2001:db8::1")
a2, _ := ipv6.Parse("2001:db8::ffff")
fmt.Println(ipv6.Distance(a1, a2))
```
Containment:
```go
outer, _ := ipv6.ParseCIDR("2001:db8::/48")
inner, _ := ipv6.ParseCIDR("2001:db8:0:1::/64")
fmt.Println(outer.ContainsCIDR(inner))
```

## Output Formats
Default is human-readable. Use `-o json` or `-o yaml` for structured output.

## Testing
```
go test ./...
```
Coverage report:
```
go test ./ipv6 -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Contributing
1. Open an issue or PR
2. Add tests for changes
3. Run `go fmt` / `go vet`

## License
MIT
