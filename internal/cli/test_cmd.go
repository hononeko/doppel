package cli

import (
	"github.com/hononeko/doppel/internal/accounts"
	"github.com/hononeko/doppel/internal/ops"
	"github.com/hononeko/doppel/internal/store"
	"github.com/hononeko/doppel/internal/ui"
)

const testUsage = "doppel test [<id>] [--json]"

type testCheckJSON struct {
	Label   string `json:"label"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix,omitempty"`
}

type testAccountJSON struct {
	Account string          `json:"account"`
	OK      bool            `json:"ok"`
	Checks  []testCheckJSON `json:"checks"`
	Hints   []string        `json:"hints,omitempty"`
}

type testJSON struct {
	Accounts []testAccountJSON `json:"accounts"`
	OK       bool              `json:"ok"`
}

// cmdTest tries each account's keys for real: it logs in to every host and
// signs a test message, then verifies it as Git would.
func (a *app) cmdTest(args []string) int {
	fs := newFlagSet("test")
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "output test results as JSON")
	positional, code, ok := a.parseCommand(fs, args, testUsage)
	if !ok {
		return code
	}
	if len(positional) > 1 {
		return a.usageError(testUsage)
	}
	list, err := accounts.Load(a.env)
	if err != nil {
		return a.fail(err)
	}
	if len(positional) == 1 {
		acc, err := ops.Find(list, positional[0])
		if err != nil {
			return a.fail(err)
		}
		list = []*accounts.Account{acc}
	}
	if len(list) == 0 {
		if asJSON {
			return a.printJSON(testJSON{Accounts: []testAccountJSON{}, OK: true})
		}
		a.printf("No accounts to test.\n")
		return 0
	}
	signers, _, err := store.SignersFile(a.env)
	if err != nil {
		return a.fail(err)
	}

	ctx := a.opsContext(writeFlags{})
	failed := false
	jsonAccounts := make([]testAccountJSON, 0, len(list))
	for i, acc := range list {
		if asJSON {
			checks := []testCheckJSON{}
			accFailed := ops.Test(ctx, acc, signers, func(c ops.Check) {
				checks = append(checks, testCheckJSON{
					Label:   c.Label,
					OK:      c.OK,
					Skipped: c.Skipped,
					Detail:  c.Detail,
					Fix:     c.Fix,
				})
			})
			if accFailed {
				failed = true
			}
			jsonAccounts = append(jsonAccounts, testAccountJSON{
				Account: acc.ID,
				OK:      !accFailed,
				Checks:  checks,
				Hints:   ops.KeychainHints(ctx, acc.AuthKey, acc.SigningKey),
			})
			continue
		}
		if i > 0 {
			a.printf("\n")
		}
		a.printf("%s\n", ui.Accent.Render(acc.ID))
		if ops.Test(ctx, acc, signers, a.checkRow) {
			failed = true
		}
		// Without a terminal, the rows above already name the command.
		if a.interactive {
			for _, hint := range ops.KeychainHints(ctx, acc.AuthKey, acc.SigningKey) {
				a.notef("  %s", hint)
			}
		}
	}
	if asJSON {
		if code := a.printJSON(testJSON{Accounts: jsonAccounts, OK: !failed}); code != 0 {
			return code
		}
	}
	if failed {
		return 1
	}
	return 0
}

// checkRow shows the outcome of one check.
func (a *app) checkRow(c ops.Check) {
	switch {
	case c.Skipped:
		a.printf("  %s %-12s %s\n", ui.Dim.Render("–"), c.Label, ui.Dim.Render(c.Detail))
	case c.OK:
		a.printf("  %s %-12s %s\n", ui.OK.Render("✓"), c.Label, c.Detail)
	default:
		a.printf("  %s %-12s %s\n", ui.Error.Render("✗"), c.Label, c.Detail)
	}
}
