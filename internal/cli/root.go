package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/zlobste/ip6calc/ipv6"
)

type outputFormat string

const (
	outHuman outputFormat = "human"
	outJSON  outputFormat = "json"
	outYAML  outputFormat = "yaml"
)

var rootCmd = &cobra.Command{
	Use:   "ip6calc",
	Short: "IPv6 subnet calculator and utility tool",
	Long:  "ip6calc provides IPv6 address and network calculations (expand, split, summarize, arithmetic, etc).",
}

var format outputFormat

// Execute runs the root command tree.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP((*string)(&format), "output", "o", string(outHuman), "output format: human|json|yaml")
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(expandCmd)
	rootCmd.AddCommand(compressCmd)
	rootCmd.AddCommand(splitCmd)
	rootCmd.AddCommand(summarizeCmd)
	rootCmd.AddCommand(reverseCmd)
}

func render(v any) error {
	w := rootCmd.OutOrStdout()
	switch format {
	case outHuman:
		fmt.Fprintln(w, v)
	case outJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case outYAML:
		enc := yaml.NewEncoder(w)
		defer enc.Close()
		return enc.Encode(v)
	default:
		return errors.New("unknown output format")
	}
	return nil
}

// ---- Commands ----

var infoCmd = &cobra.Command{
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

var expandCmd = &cobra.Command{
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

var compressCmd = &cobra.Command{
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

var splitCmd = &cobra.Command{
	Use:   "split <IPv6 CIDR>",
	Short: "Split a network into smaller subnets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		newPrefix, _ := cmd.Flags().GetInt("new-prefix")
		c, err := ipv6.ParseCIDR(args[0])
		if err != nil {
			return err
		}
		subs, err := c.Split(newPrefix)
		if err != nil {
			return err
		}
		list := make([]string, len(subs))
		for i, s := range subs {
			list[i] = s.String()
		}
		return render(list)
	},
}

var summarizeCmd = &cobra.Command{
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

var reverseCmd = &cobra.Command{
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

func init() {
	splitCmd.Flags().Int("new-prefix", 0, "new prefix length to split into (must be larger than original)")
}
