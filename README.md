# ip6calc

IPv6 subnet calculator and Go library. Command line tool plus package for parsing, formatting, subnet math, summarization and basic analysis of IPv6 networks.

## Features
- Parse / validate IPv6 addresses and CIDRs (sentinel errors: ErrInvalidAddress, ErrInvalidCIDR, etc.)
- Expand / compress addresses
- Network base, first, last, count of addresses
- Address arithmetic (add / subtract / offset) (library) with fast uint64 paths
- Adjacent network navigation (next / prev) (library)
- Split a network into smaller subnets (iterator or full slice)
- Summarize sibling networks
- Containment and overlap checks (library) with simplified interval overlap logic
- Reverse DNS (ip6.arpa) name generation
- Output: human (line-per-item lists), JSON, YAML
- Shell completion scripts (bash, zsh, fish, powershell)
- Man page generation command
- Version command (build-time ldflags)
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
- split       split a CIDR into smaller prefixes (requires --new-prefix > original)
- summarize   merge a set of CIDRs
- reverse     ip6.arpa reverse DNS name
- version     print version info
- completion  generate shell completion script
- man         generate man pages into a directory

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

# Generate bash completion
ip6calc completion bash > /etc/bash_completion.d/ip6calc

# Generate man pages
ip6calc man ./manpages

# Version
ip6calc version
```

## Library
Constructor pattern for CLI embedding:
```go
cmd := cli.NewRootCmd(os.Stdout)
cmd.Execute()
```
Basic inspection:
```go
cidr, _ := ipv6.ParseCIDR("2001:db8::/64")
fmt.Println(cidr.Network())
fmt.Println(cidr.FirstHost())
fmt.Println(cidr.LastHost())
fmt.Println(cidr.HostCount())
```
Subnet iteration (memory efficient):
```go
c, _ := ipv6.ParseCIDR("2001:db8::/120")
it, _ := c.SubnetIterator(124)
for {
  sub, ok := it.Next()
  if !ok { break }
  fmt.Println(sub)
}
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
Lists (e.g. split results) print one item per line in human mode.

## Version Info
Injected at build time:
```
go build -ldflags "-X github.com/zlobste/ip6calc/internal/cli.Version=v1.2.3" ./cmd/ip6calc
```

## Testing
```
go test ./...
```
Coverage report:
```
go test ./ipv6 -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## License
MIT (see LICENSE file)
