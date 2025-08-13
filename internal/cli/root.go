package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

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

// Version gets overridden via -ldflags at build time (e.g. -X github.com/zlobste/ip6calc/internal/cli.Version=v1.2.3)
var Version = "dev"

// NewRootCmd constructs a new *cobra.Command tree with isolated state.
func NewRootCmd(out io.Writer) *cobra.Command {
	var format outputFormat

	rootCmd := &cobra.Command{
		Use:   "ip6calc",
		Short: "IPv6 subnet calculator and utility tool",
		Long:  "ip6calc provides IPv6 address and network calculations (expand, split, summarize, arithmetic, etc).",
	}

	rootCmd.SetOut(out)
	rootCmd.PersistentFlags().StringVarP((*string)(&format), "output", "o", string(outHuman), "output format: human|json|yaml")

	// Rendering helper closure bound to this command's writer & format.
	render := func(v any) error {
		w := rootCmd.OutOrStdout()
		switch format {
		case outHuman:
			// If slice of strings, print each on its own line for readability.
			rv := reflect.ValueOf(v)
			if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.String {
				for i := 0; i < rv.Len(); i++ {
					if _, err := fmt.Fprintln(w, rv.Index(i).Interface()); err != nil {
						return err
					}
				}
				return nil
			}
			if _, err := fmt.Fprintln(w, v); err != nil {
				return err
			}
		case outJSON:
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		case outYAML:
			enc := yaml.NewEncoder(w)
			if err := enc.Encode(v); err != nil {
				_ = enc.Close()
				return err
			}
			return enc.Close()
		default:
			return errors.New("unknown output format")
		}
		return nil
	}

	// ---- Commands ----

	infoCmd := &cobra.Command{
		Use:   "info <IPv6 CIDR or address>",
		Short: "Show information about an IPv6 address or network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := args[0]
			if strings.Contains(arg, "/") {
				c, err := ipv6.ParseCIDR(arg)
				if err != nil {
					return err
				}
				out := map[string]any{
					"network":       c.Network().String(),
					"prefix_length": c.PrefixLength(),
					"first_host":    c.FirstHost().String(),
					"last_host":     c.LastHost().String(),
					"host_count":    c.HostCount().String(),
				}
				return render(out)
			}
			addr, err := ipv6.Parse(arg)
			if err != nil {
				return err
			}
			out := map[string]any{
				"address":  addr.String(),
				"expanded": addr.Expanded(),
				"reverse":  addr.ReverseDNS(),
			}
			return render(out)
		},
	}

	expandCmd := &cobra.Command{
		Use:   "expand <IPv6 address>",
		Short: "Expand a compressed IPv6 address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := ipv6.Parse(args[0])
			if err != nil {
				return err
			}
			return render(addr.Expanded())
		},
	}

	compressCmd := &cobra.Command{
		Use:   "compress <expanded IPv6>",
		Short: "Compress an expanded IPv6 address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := ipv6.Parse(args[0])
			if err != nil {
				return err
			}
			return render(addr.String())
		},
	}

	splitCmd := &cobra.Command{
		Use:     "split <IPv6 CIDR>",
		Short:   "Split a network into smaller subnets",
		Args:    cobra.ExactArgs(1),
		Example: "  # Split /48 into /52\n  ip6calc split 2001:db8::/48 --new-prefix 52",
		RunE: func(cmd *cobra.Command, args []string) error {
			newPrefix, _ := cmd.Flags().GetInt("new-prefix")
			c, err := ipv6.ParseCIDR(args[0])
			if err != nil {
				return err
			}
			if newPrefix == 0 || newPrefix <= c.PrefixLength() || newPrefix > 128 {
				return fmt.Errorf("invalid --new-prefix: must be > original (%d) and <=128", c.PrefixLength())
			}
			// Use iterator to avoid allocating huge slices.
			it, err := c.SubnetIterator(newPrefix)
			if err != nil {
				return err
			}
			// Collect while keeping a safety cap; if large, stream line by line in human mode.
			var list []string
			capCollect := 4096
			for parts := 0; ; parts++ {
				sub, ok := it.Next()
				if !ok {
					break
				}
				if format == outHuman && parts >= capCollect {
					// Switch to streaming for human output.
					fmt.Fprintln(rootCmd.OutOrStdout(), sub.String())
					continue
				}
				list = append(list, sub.String())
			}
			if format == outHuman && len(list) > capCollect {
				return nil // already streamed remaining.
			}
			return render(list)
		},
	}
	splitCmd.Flags().Int("new-prefix", 0, "new prefix length to split into (must be larger than original)")

	summarizeCmd := &cobra.Command{
		Use:   "summarize <CIDR 1> <CIDR 2> ...",
		Short: "Summarize a list of CIDRs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cidrs := make([]ipv6.CIDR, 0, len(args))
			for _, a := range args {
				c, err := ipv6.ParseCIDR(a)
				if err != nil {
					return err
				}
				cidrs = append(cidrs, c)
			}
			res := ipv6.Summarize(cidrs)
			list := make([]string, len(res))
			for i, s := range res {
				list[i] = s.String()
			}
			return render(list)
		},
	}

	reverseCmd := &cobra.Command{
		Use:   "reverse <IPv6 address>",
		Short: "Produce reverse DNS ip6.arpa name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := ipv6.Parse(args[0])
			if err != nil {
				return err
			}
			return render(addr.ReverseDNS())
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			return render(map[string]string{"version": Version})
		},
	}

	completionCmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
		},
	}

	manCmd := &cobra.Command{
		Use:   "man <directory>",
		Short: "Generate man pages into the provided directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			header := &doc.GenManHeader{Title: "IP6CALC", Section: "1"}
			return doc.GenManTree(rootCmd, header, dir)
		},
	}

	rootCmd.AddCommand(infoCmd, expandCmd, compressCmd, splitCmd, summarizeCmd, reverseCmd, versionCmd, completionCmd, manCmd)
	return rootCmd
}

// Execute builds and runs the CLI using os.Stdout.
func Execute() {
	cmd := NewRootCmd(os.Stdout)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
