package bundle

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

const compareCommandName = "bundle compare"

// NewCompareCommand creates a new "compare" subcommand for "bundle". The
// command runs entirely offline: it reads two SPIFFE-format bundle files and
// reports their semantic differences without contacting a SPIRE server,
// updating a bundle, or merging the two files.
func NewCompareCommand() cli.Command {
	return newCompareCommand(common_cli.DefaultEnv)
}

func newCompareCommand(env *common_cli.Env) *compareCommand {
	return &compareCommand{env: env}
}

type compareCommand struct {
	env *common_cli.Env

	// firstPath and secondPath are the paths of the two SPIFFE-format bundle
	// files to compare. A value of "-" means the bundle is read from stdin.
	firstPath  string
	secondPath string
	// firstTD and secondTD optionally declare the trust domains of the two
	// bundles, since the trust domain is not conveyed as part of the SPIFFE
	// bundle format. When secondTD is empty, it defaults to firstTD.
	firstTD  string
	secondTD string

	printer cliprinter.Printer
}

func (c *compareCommand) Name() string {
	return compareCommandName
}

func (c *compareCommand) Synopsis() string {
	return "Compares two SPIFFE-format trust bundle files without contacting the server"
}

func (c *compareCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.firstPath, "first", "", "Path to the first SPIFFE-format bundle file. Use \"-\" to read it from stdin.")
	fs.StringVar(&c.secondPath, "second", "", "Path to the second SPIFFE-format bundle file. Use \"-\" to read it from stdin.")
	fs.StringVar(&c.firstTD, "firstTrustDomain", "", "Trust domain of the first bundle (e.g. \"example.org\" or \"spiffe://example.org\"). Optional; the trust domain is not part of the SPIFFE bundle format.")
	fs.StringVar(&c.secondTD, "secondTrustDomain", "", "Trust domain of the second bundle. Defaults to -firstTrustDomain. Comparison is rejected when the two trust domains differ.")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintDiff)
}

func (c *compareCommand) newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(compareCommandName, flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage: %s -first <path> -second <path> [flags]\n", compareCommandName)
		fmt.Fprintln(out, `
Semantically compares two SPIFFE-format trust bundle files entirely offline.
No server is contacted, no bundle is updated, and the files are not merged.

The report lists, separately for X.509 CA certificates, JWT verification keys,
and WIT verification keys, the entries that were added, removed, or changed.
Certificates are identified by their full contents; public keys are compared by
key ID within their use and by their actual key material (a key ID whose key
material changed is reported as a change). Entry order and JSON formatting do
not produce differences. Sequence number and refresh hint changes are reported
separately as metadata.

Exit status: 0 if the bundles are semantically identical, 1 if the input is
invalid, and 2 if differences were found.`)
		fs.PrintDefaults()
	}
	c.AppendFlags(fs)
	return fs
}

func (c *compareCommand) Help() string {
	return c.newFlagSet().Parse([]string{"-h"}).Error()
}

func (c *compareCommand) Run(args []string) int {
	fs := c.newFlagSet()
	if err := fs.Parse(args); err != nil {
		return bundleutil.CompareExitCodeInvalid
	}

	diff, err := c.compare(fs.Args())
	if err != nil {
		_ = c.env.ErrPrintln("Error: " + err.Error())
		return bundleutil.CompareExitCodeInvalid
	}

	if err := c.printer.PrintStruct(diff); err != nil {
		_ = c.env.ErrPrintln("Error: " + err.Error())
		return bundleutil.CompareExitCodeInvalid
	}

	if diff.HasDifferences() {
		return bundleutil.CompareExitCodeDifferent
	}
	return bundleutil.CompareExitCodeIdentical
}

func (c *compareCommand) compare(positional []string) (*bundleutil.Diff, error) {
	if c.firstPath == "" || c.secondPath == "" {
		return nil, errors.New("both -first and -second bundle paths are required")
	}
	if c.firstPath == "-" && c.secondPath == "-" {
		return nil, errors.New("only one of -first or -second can be read from stdin")
	}
	if len(positional) != 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(positional, " "))
	}

	firstTD, err := trustDomainFromFlag(c.firstTD)
	if err != nil {
		return nil, fmt.Errorf("invalid -firstTrustDomain %q: %w", c.firstTD, err)
	}
	secondTDName := c.secondTD
	if secondTDName == "" {
		secondTDName = c.firstTD
	}
	secondTD, err := trustDomainFromFlag(secondTDName)
	if err != nil {
		return nil, fmt.Errorf("invalid -secondTrustDomain %q: %w", secondTDName, err)
	}
	if firstTD != secondTD {
		return nil, fmt.Errorf("%w: %q vs %q", bundleutil.ErrDifferentTrustDomains,
			firstTD.Name(), secondTD.Name())
	}

	firstBytes, err := c.loadBundle(c.firstPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load first bundle %s: %w", bundlePathForError(c.firstPath), err)
	}
	secondBytes, err := c.loadBundle(c.secondPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load second bundle %s: %w", bundlePathForError(c.secondPath), err)
	}

	firstBundle, err := spiffebundle.Parse(firstTD, firstBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse first bundle %s: %w", bundlePathForError(c.firstPath), err)
	}
	secondBundle, err := spiffebundle.Parse(secondTD, secondBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse second bundle %s: %w", bundlePathForError(c.secondPath), err)
	}

	return bundleutil.Compare(firstBundle, secondBundle)
}

func (c *compareCommand) loadBundle(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(c.env.Stdin)
	}
	return os.ReadFile(path)
}

func trustDomainFromFlag(value string) (spiffeid.TrustDomain, error) {
	if value == "" {
		return spiffeid.TrustDomain{}, nil
	}
	return spiffeid.TrustDomainFromString(value)
}

func bundlePathForError(path string) string {
	if path == "-" {
		return "<stdin>"
	}
	return path
}

func (c *compareCommand) prettyPrintDiff(env *common_cli.Env, results ...any) error {
	diff, ok := results[0].(*bundleutil.Diff)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	return writePrettyDiff(env.Stdout, diff)
}
