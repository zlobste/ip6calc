package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"gopkg.in/yaml.v3"

	"github.com/zlobste/ip6calc/ipv6"
)

type outputFormat string

const (
	outHuman outputFormat = "human"
	outJSON  outputFormat = "json"
	outYAML  outputFormat = "yaml"
)

// Set implements pflag.Value for validation.
func (o *outputFormat) Set(v string) error {
	switch v {
	case string(outHuman), string(outJSON), string(outYAML):
		*o = outputFormat(v)
		return nil
	default:
		return fmt.Errorf("invalid output format: %s", v)
	}
}
func (o *outputFormat) String() string { return string(*o) }
func (o *outputFormat) Type() string   { return "outputFormat" }

// Version gets overridden via -ldflags at build time (e.g. -X github.com/zlobste/ip6calc/internal/cli.Version=v1.2.3)
var Version = "dev"

// Commit and BuildDate can also be injected (optional)
var (
	Commit    = ""
	BuildDate = ""
)

// Custom error for oversized split operations requiring --force.
var ErrSplitTooLarge = errors.New("split: too many subnets without --force")

// OverlapError indicates CIDR overlap when --fail-on-overlap is requested.
type OverlapError struct{ A, B ipv6.CIDR }

func (e OverlapError) Error() string { return fmt.Sprintf("overlap detected: %s %s", e.A, e.B) }

// Exit codes for different error classes.
const (
	exitCodeInvalidInput = 2
	exitCodeOverlap      = 3
	exitCodeSplitTooBig  = 4
)

// thresholds (can be overridden via env for tests)
var (
	defaultSplitWarnThreshold  = 1 << 14 // 16,384
	defaultSplitForceThreshold = 1 << 16 // 65,536
)

// getThreshold reads an int env var or returns fallback.
func getThreshold(env string, fallback int) int {
	if v := os.Getenv(env); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// NewRootCmd constructs a new *cobra.Command tree with isolated state.
func NewRootCmd(out io.Writer) *cobra.Command {
	var format = outHuman
	var flagColor, flagTable, flagQuiet, flagNoHeader bool
	var flagUpper bool

	rootCmd := &cobra.Command{Use: "ip6calc", Short: "IPv6 subnet calculator and utility tool", Long: "ip6calc provides IPv6 address and network calculations (expand, split, summarize, arithmetic, etc)."}
	// Auto-detect format from env var if flag not supplied.
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("output") {
			if envFmt := os.Getenv("IP6CALC_FORMAT"); envFmt != "" {
				_ = format.Set(envFmt) // ignore invalid env value (explicit)
			}
		}
		return nil
	}
	rootCmd.SetOut(out)
	rootCmd.PersistentFlags().VarP(&format, "output", "o", "output format: human|json|yaml")
	rootCmd.PersistentFlags().BoolVar(&flagColor, "color", false, "colorize human output")
	rootCmd.PersistentFlags().BoolVar(&flagTable, "table", false, "tabular human output where applicable")
	rootCmd.PersistentFlags().BoolVar(&flagQuiet, "quiet", false, "suppress non-essential human output")
	rootCmd.PersistentFlags().BoolVar(&flagNoHeader, "no-header", false, "omit headers in tabular output")
	rootCmd.PersistentFlags().BoolVar(&flagUpper, "upper", false, "use uppercase expanded form where relevant")

	// helper for colored text
	colorize := func(s string) string {
		if !flagColor || format != outHuman {
			return s
		}
		return "\x1b[36m" + s + "\x1b[0m"
	}

	// host count formatting
	formatHostCount := func(n *big.Int) (raw string, power string, approx string) {
		raw = n.String()
		// power-of-two detection: n>0 and n&(n-1)==0
		if n.Sign() > 0 {
			m := new(big.Int).Sub(n, big.NewInt(1))
			if new(big.Int).And(m, n).Sign() == 0 { // exact power of two
				power = fmt.Sprintf("2^%d", n.BitLen()-1)
			}
		}
		// approximate decimal (scientific)
		if n.Sign() == 0 {
			approx = "0"
		} else {
			ln10 := new(big.Float).SetFloat64(10)
			bf := new(big.Float).SetInt(n)
			exp := 0
			for bf.Cmp(ln10) >= 0 {
				bf.Quo(bf, ln10)
				exp++
			}
			f, _ := bf.Float64()
			approx = fmt.Sprintf("%.2fe%d", f, exp)
		}
		return
	}

	// Rendering helper closure bound to this command's writer & format.
	render := func(v any) error {
		w := rootCmd.OutOrStdout()
		schemaWrap := func(obj any) any {
			if format == outJSON || format == outYAML {
				if m, ok := obj.(map[string]any); ok {
					merged := make(map[string]any, len(m)+1)
					for k, v := range m {
						merged[k] = v
					}
					merged["schema"] = "ip6calc/v1"
					return merged
				}
				return map[string]any{"schema": "ip6calc/v1", "data": obj}
			}
			return obj
		}
		switch format {
		case outHuman, "":
			if flagQuiet {
				return nil
			}
			rv := reflect.ValueOf(v)
			if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.String {
				if flagTable {
					width := 0
					for i := 0; i < rv.Len(); i++ {
						if l := len(rv.Index(i).String()); l > width {
							width = l
						}
					}
					if !flagNoHeader && rv.Len() > 0 {
						if _, err := fmt.Fprintf(w, "%4s  %-*s\n", "Idx", width, "Value"); err != nil {
							return err
						}
					}
					for i := 0; i < rv.Len(); i++ {
						if _, err := fmt.Fprintf(w, "%4d  %-*s\n", i+1, width, rv.Index(i).String()); err != nil {
							return err
						}
					}
					return nil
				}
				for i := 0; i < rv.Len(); i++ {
					if _, err := fmt.Fprintln(w, rv.Index(i).Interface()); err != nil {
						return err
					}
				}
				return nil
			}
			_, _ = fmt.Fprintln(w, v)
		case outJSON:
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(schemaWrap(v))
		case outYAML:
			enc := yaml.NewEncoder(w)
			if err := enc.Encode(schemaWrap(v)); err != nil {
				_ = enc.Close()
				return err
			}
			if err := enc.Close(); err != nil { // capture close error
				return err
			}
		default:
			return errors.New("unknown output format")
		}
		return nil
	}

	readStdinLines := func() ([]string, error) {
		info, err := os.Stdin.Stat()
		if err != nil {
			return nil, err
		}
		if (info.Mode() & os.ModeCharDevice) != 0 {
			return nil, nil
		}
		scanner := bufio.NewScanner(os.Stdin)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}
		return lines, scanner.Err()
	}

	// ---- Commands ----

	infoCmd := &cobra.Command{Use: "info <IPv6 CIDR or address>", Short: "Show information about an IPv6 address or network", Args: cobra.MaximumNArgs(1), Example: "  ip6calc info 2001:db8::/64\n  ip6calc info 2001:db8::1", RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 { // try stdin
			lines, err := readStdinLines()
			if err != nil {
				return err
			}
			if len(lines) == 0 {
				return errors.New("no input")
			}
			args = []string{lines[0]}
		}
		arg := args[0]
		if strings.Contains(arg, "/") {
			c, err := ipv6.ParseCIDR(arg)
			if err != nil {
				return err
			}
			raw, power, approx := formatHostCount(c.HostCount())
			out := map[string]any{"network": c.Network().String(), "prefix_length": c.PrefixLength(), "first_host": c.FirstHost().String(), "last_host": c.LastHost().String(), "host_count": raw, "host_count_power": power, "host_count_approx": approx}
			return render(out)
		}
		addr, err := ipv6.Parse(arg)
		if err != nil {
			return err
		}
		exp := addr.Expanded()
		if flagUpper {
			exp = addr.ExpandedUpper()
		}
		out := map[string]any{"address": addr.String(), "expanded": exp, "reverse": addr.ReverseDNS()}
		return render(out)
	}}

	expandCmd := &cobra.Command{Use: "expand [IPv6 address ...]", Short: "Expand compressed IPv6 address(es)", Args: cobra.ArbitraryArgs, Example: "  ip6calc expand 2001:db8::1 2001:db8::2\n  echo 2001:db8::1 | ip6calc expand", RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			lines, err := readStdinLines()
			if err != nil {
				return err
			}
			args = lines
		}
		var list []string
		for _, a := range args {
			if a == "" {
				continue
			}
			addr, err := ipv6.Parse(a)
			if err != nil {
				return err
			}
			list = append(list, addr.Expanded())
		}
		return render(list)
	}}

	compressCmd := &cobra.Command{Use: "compress [IPv6 address ...]", Short: "Compress IPv6 address(es)", Args: cobra.ArbitraryArgs, Example: "  ip6calc compress 2001:0db8:0000:0000:0000:0000:0000:0001", RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			lines, err := readStdinLines()
			if err != nil {
				return err
			}
			args = lines
		}
		var list []string
		for _, a := range args {
			if a == "" {
				continue
			}
			addr, err := ipv6.Parse(a)
			if err != nil {
				return err
			}
			list = append(list, addr.String())
		}
		return render(list)
	}}

	// Split command adjusted to allow equal new-prefix and handle ErrSplitExcessive.
	splitCmd := &cobra.Command{Use: "split <IPv6 CIDR>", Short: "Split a network into smaller subnets", Args: cobra.ExactArgs(1), Example: "  # Split /48 into /52\n  ip6calc split 2001:db8::/48 --new-prefix 52", RunE: func(cmd *cobra.Command, args []string) error {
		newPrefix, _ := cmd.Flags().GetInt("new-prefix")
		force, _ := cmd.Flags().GetBool("force")
		c, err := ipv6.ParseCIDR(args[0])
		if err != nil {
			return err
		}
		if newPrefix < c.PrefixLength() || newPrefix > 128 {
			return fmt.Errorf("invalid --new-prefix: must be >= original (%d) and <=128", c.PrefixLength())
		}
		// delegate capacity / sanity checks to library after computing diff
		diff := newPrefix - c.PrefixLength()
		if diff >= 63 { // early guard matching library
			return ipv6.ErrSplitExcessive
		}
		// compute parts using uint64 for safety
		parts := uint64(1)
		if diff > 0 {
			parts = uint64(1) << uint(diff)
		}
		warnThreshold := getThreshold("IP6CALC_SPLIT_WARN_THRESHOLD", defaultSplitWarnThreshold)
		forceThreshold := getThreshold("IP6CALC_SPLIT_FORCE_THRESHOLD", defaultSplitForceThreshold)
		if parts > uint64(forceThreshold) && !force {
			return ErrSplitTooLarge
		}
		if parts > uint64(warnThreshold) && format == outHuman && !force && diff > 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: generating %d subnets (use --force to suppress)\n", parts)
		}
		// For very large outputs, stream instead of buffering entire slice for human output.
		streamThreshold := uint64(forceThreshold) / 2
		if parts > streamThreshold && format == outHuman && !force && !flagTable && diff > 0 {
			it, err := c.SubnetIterator(newPrefix)
			if err != nil {
				return err
			}
			w := rootCmd.OutOrStdout()
			progressEvery := int(parts / 10)
			if progressEvery == 0 {
				progressEvery = 1
			}
			count := 0
			for {
				sub, ok := it.Next()
				if !ok {
					break
				}
				count++
				if _, err := fmt.Fprintln(w, sub.String()); err != nil {
					return err
				}
				if count%progressEvery == 0 && parts > 1 {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "progress: %d/%d (%.0f%%)\n", count, parts, float64(count)*100/float64(parts))
				}
			}
			return nil
		}
		// Use library Split (handles equality case now)
		subs, err := c.Split(newPrefix)
		if err != nil {
			return err
		}
		var list []string
		for _, s := range subs {
			list = append(list, s.String())
		}
		return render(list)
	}}
	splitCmd.Flags().Int("new-prefix", 0, "new prefix length to split into (must be larger than original)")
	splitCmd.Flags().Bool("force", false, "proceed even if subnet count exceeds large threshold")

	summarizeCmd := &cobra.Command{Use: "summarize <CIDR...>", Short: "Summarize a list of CIDRs", Args: cobra.MinimumNArgs(1), Example: "  ip6calc summarize 2001:db8::/65 2001:db8:0:0:8000::/65", RunE: func(cmd *cobra.Command, args []string) error {
		failOverlap, _ := cmd.Flags().GetBool("fail-on-overlap")
		cidrs := make([]ipv6.CIDR, 0, len(args))
		for _, a := range args {
			c, err := ipv6.ParseCIDR(a)
			if err != nil {
				return err
			}
			cidrs = append(cidrs, c)
		}
		if failOverlap {
			for i := 0; i < len(cidrs); i++ {
				for j := i + 1; j < len(cidrs); j++ {
					if cidrs[i].Overlaps(cidrs[j]) { // treat any overlap (including containment) as error
						return OverlapError{cidrs[i], cidrs[j]}
					}
				}
			}
		}
		res := ipv6.Summarize(cidrs)
		list := make([]string, len(res))
		for i, s := range res {
			list[i] = s.String()
		}
		return render(list)
	}}
	summarizeCmd.Flags().Bool("fail-on-overlap", false, "fail if any overlapping (non-contained) CIDRs present")

	reverseCmd := &cobra.Command{Use: "reverse <IPv6 address>", Short: "Produce reverse DNS ip6.arpa name", Args: cobra.ExactArgs(1), Example: "  ip6calc reverse 2001:db8::1\n  ip6calc reverse --zone 2001:db8::1", RunE: func(cmd *cobra.Command, args []string) error {
		zone, _ := cmd.Flags().GetBool("zone")
		addr, err := ipv6.Parse(args[0])
		if err != nil {
			return err
		}
		rev := addr.ReverseDNS()
		if zone {
			rev = strings.TrimSuffix(rev, ".")
		}
		return render(rev)
	}}
	reverseCmd.Flags().Bool("zone", false, "omit trailing dot for zonefile usage")

	toIntCmd := &cobra.Command{Use: "to-int <IPv6 address>", Short: "Convert IPv6 address to integer", Args: cobra.ExactArgs(1), Example: "  ip6calc to-int 2001:db8::1", RunE: func(cmd *cobra.Command, args []string) error {
		addr, err := ipv6.Parse(args[0])
		if err != nil {
			return err
		}
		return render(addr.BigInt().String())
	}}

	fromIntCmd := &cobra.Command{Use: "from-int <integer>", Short: "Convert integer to IPv6 address", Args: cobra.ExactArgs(1), Example: "  ip6calc to-int 2001:db8::1 | ip6calc from-int", RunE: func(cmd *cobra.Command, args []string) error {
		bi, ok := new(big.Int).SetString(args[0], 10)
		if !ok {
			return errors.New("invalid integer")
		}
		addr, err := ipv6.AddressFromBigInt(bi)
		if err != nil {
			return err
		}
		return render(addr.String())
	}}

	rangeCmd := &cobra.Command{Use: "range <start-end>", Short: "Cover address range with minimal CIDRs", Args: cobra.ExactArgs(1), Example: "  ip6calc range 2001:db8::1-2001:db8::ff", RunE: func(cmd *cobra.Command, args []string) error {
		parts := strings.Split(args[0], "-")
		if len(parts) != 2 {
			return errors.New("invalid range format")
		}
		start, err := ipv6.Parse(parts[0])
		if err != nil {
			return err
		}
		end, err := ipv6.Parse(parts[1])
		if err != nil {
			return err
		}
		cover, err := ipv6.CoverRange(start, end)
		if err != nil {
			return err
		}
		list := make([]string, len(cover))
		for i, c := range cover {
			list[i] = c.String()
		}
		return render(list)
	}}

	supernetCmd := &cobra.Command{Use: "supernet <CIDR...>", Short: "Smallest CIDR containing all", Args: cobra.MinimumNArgs(1), Example: "  ip6calc supernet 2001:db8::/65 2001:db8:0:0:8000::/65", RunE: func(cmd *cobra.Command, args []string) error {
		var list []ipv6.CIDR
		for _, a := range args {
			c, err := ipv6.ParseCIDR(a)
			if err != nil {
				return err
			}
			list = append(list, c)
		}
		res, err := ipv6.Supernet(list)
		if err != nil {
			return err
		}
		return render(res.String())
	}}

	enumerateCmd := &cobra.Command{Use: "enumerate <CIDR>", Short: "Enumerate sample addresses", Args: cobra.ExactArgs(1), Example: "  ip6calc enumerate 2001:db8::/64 --limit 5 --stride 16", RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		stride, _ := cmd.Flags().GetInt("stride")
		if limit <= 0 {
			return errors.New("limit must be >0")
		}
		if stride <= 0 {
			return errors.New("stride must be >0")
		}
		c, err := ipv6.ParseCIDR(args[0])
		if err != nil {
			return err
		}
		var list []string
		for i := 0; i < limit; i++ {
			delta := new(big.Int).Mul(big.NewInt(int64(stride)), big.NewInt(int64(i)))
			addr := c.FirstHost().Add(delta)
			if !c.ContainsAddress(addr) {
				break
			}
			list = append(list, addr.String())
		}
		return render(list)
	}}
	enumerateCmd.Flags().Int("limit", 10, "maximum number of addresses to emit")
	enumerateCmd.Flags().Int("stride", 1, "step between successive addresses")

	randomCmd := &cobra.Command{Use: "random", Short: "Random address or subnet"}
	// dynamic completion for random subcommands
	randomCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return []string{"address", "subnet"}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	randomAddrCmd := &cobra.Command{Use: "address <CIDR>", Short: "Random address(es) in CIDR", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		count, _ := cmd.Flags().GetInt("count")
		if count <= 0 {
			return errors.New("count must be >0")
		}
		c, err := ipv6.ParseCIDR(args[0])
		if err != nil {
			return err
		}
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		var list []string
		for i := 0; i < count; i++ {
			list = append(list, ipv6.RandomAddressInCIDR(c, r).String())
		}
		return render(list)
	}}
	randomAddrCmd.Flags().Int("count", 1, "number of random addresses")
	randomSubnetCmd := &cobra.Command{Use: "subnet <CIDR>", Short: "Random subnet in CIDR", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		count, _ := cmd.Flags().GetInt("count")
		newPrefix, _ := cmd.Flags().GetInt("new-prefix")
		if count <= 0 {
			return errors.New("count must be >0")
		}
		c, err := ipv6.ParseCIDR(args[0])
		if err != nil {
			return err
		}
		if newPrefix == 0 {
			return errors.New("--new-prefix required")
		}
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		var list []string
		for i := 0; i < count; i++ {
			s, err := ipv6.RandomSubnetInCIDR(c, newPrefix, r)
			if err != nil {
				return err
			}
			list = append(list, s.String())
		}
		return render(list)
	}}
	randomSubnetCmd.Flags().Int("count", 1, "number of random subnets")
	randomSubnetCmd.Flags().Int("new-prefix", 0, "prefix length of random subnets")
	randomCmd.AddCommand(randomAddrCmd, randomSubnetCmd)

	diffCmd := &cobra.Command{Use: "diff <CIDR...>", Short: "Show overlaps and gaps between CIDRs", Args: cobra.MinimumNArgs(2), Example: "  ip6calc diff 2001:db8::/65 2001:db8::/64", RunE: func(cmd *cobra.Command, args []string) error {
		var list []ipv6.CIDR
		for _, a := range args {
			c, err := ipv6.ParseCIDR(a)
			if err != nil {
				return err
			}
			list = append(list, c)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Base().Compare(list[j].Base()) == 0 {
				return list[i].PrefixLength() < list[j].PrefixLength()
			}
			return list[i].Base().Compare(list[j].Base()) < 0
		})
		type gap struct{ Start, End string }
		var overlaps []string
		var gaps []gap
		for i := 0; i < len(list)-1; i++ {
			a := list[i]
			b := list[i+1]
			if a.Overlaps(b) {
				overlaps = append(overlaps, fmt.Sprintf("%s %s", a, b))
			} else {
				ga := a.LastHost().Add(big.NewInt(1))
				gb := b.FirstHost().Sub(big.NewInt(1))
				if ga.Compare(gb) <= 0 {
					gaps = append(gaps, gap{ga.String(), gb.String()})
				}
			}
		}
		if format == outHuman {
			var lines []string
			for _, o := range overlaps {
				lines = append(lines, colorize("overlap: ")+o)
			}
			for _, g := range gaps {
				lines = append(lines, colorize("gap: ")+g.Start+"-"+g.End)
			}
			return render(lines)
		}
		return render(map[string]any{"overlaps": overlaps, "gaps": gaps})
	}}

	versionCmd := &cobra.Command{Use: "version", Short: "Print version information", RunE: func(cmd *cobra.Command, args []string) error {
		return render(map[string]string{"version": Version, "commit": Commit, "build_date": BuildDate})
	}}

	completionCmd := &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Short: "Generate shell completion script", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		w := rootCmd.OutOrStdout()
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(w)
		case "zsh":
			return rootCmd.GenZshCompletion(w)
		case "fish":
			return rootCmd.GenFishCompletion(w, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(w)
		default:
			return fmt.Errorf("unsupported shell: %s", args[0])
		}
	}}

	docsCmd := &cobra.Command{Use: "docs <directory>", Short: "Generate Markdown documentation for commands", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		dir := args[0]
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		root := cmd.Root()
		root.DisableAutoGenTag = true
		return doc.GenMarkdownTree(root, dir)
	}}

	manCmd := &cobra.Command{Use: "man <directory>", Short: "Generate man pages", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		dir := args[0]
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		root := cmd.Root()
		root.DisableAutoGenTag = true
		header := &doc.GenManHeader{Title: "IP6CALC", Section: "1"}
		return doc.GenManTree(root, header, dir)
	}}

	rootCmd.AddCommand(infoCmd, expandCmd, compressCmd, splitCmd, summarizeCmd, reverseCmd, toIntCmd, fromIntCmd, rangeCmd, supernetCmd, enumerateCmd, randomCmd, diffCmd, versionCmd, completionCmd, docsCmd, manCmd)
	return rootCmd
}

// Execute builds and runs the CLI using os.Stdout.
func Execute() {
	cmd := NewRootCmd(os.Stdout)
	if err := cmd.Execute(); err != nil {
		code := 1
		switch {
		case errors.Is(err, ipv6.ErrInvalidAddress), errors.Is(err, ipv6.ErrInvalidCIDR), errors.Is(err, ipv6.ErrInvalidPrefix), errors.Is(err, ipv6.ErrInvalidSplitPrefix):
			code = exitCodeInvalidInput
		case errors.Is(err, ErrSplitTooLarge), errors.Is(err, ipv6.ErrSplitExcessive):
			code = exitCodeSplitTooBig
		case errors.As(err, new(OverlapError)):
			code = exitCodeOverlap
		}
		fmt.Fprintf(os.Stderr, "ip6calc: %v\n", err)
		os.Exit(code)
	}
}
