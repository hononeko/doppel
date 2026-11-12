package cli

import (
	"fmt"

	"charm.land/huh/v2"
	"github.com/hononeko/doppel/internal/accounts"
	"github.com/hononeko/doppel/internal/keys"
	"github.com/hononeko/doppel/internal/ops"
)

const loadUsage = "doppel load <id> [--auth | --signing]"

// cmdLoad loads an account's keys into ssh-agent with ssh-add.
func (a *app) cmdLoad(args []string) int {
	fs := newFlagSet("load")
	var onlyAuth, onlySigning bool
	fs.BoolVar(&onlyAuth, "auth", false, "only the auth key")
	fs.BoolVar(&onlySigning, "signing", false, "only the signing key")
	positional, code, ok := a.parseCommand(fs, args, loadUsage)
	if !ok {
		return code
	}
	if len(positional) != 1 || (onlyAuth && onlySigning) {
		return a.usageError(loadUsage)
	}
	if _, err := a.loadAccount(positional[0], onlyAuth, onlySigning); err != nil {
		return a.fail(err)
	}
	return 0
}

// loadAccount resolves and loads an account's keys into ssh-agent. When an
// interactive call without --auth or --signing has two unloaded keys on disk,
// it asks whether to load both or just one.
func (a *app) loadAccount(id string, onlyAuth, onlySigning bool) (*ops.Result, error) {
	list, err := accounts.Load(a.env)
	if err != nil {
		return nil, err
	}
	acc, err := ops.Find(list, id)
	if err != nil {
		return nil, err
	}
	ctx := a.opsContext(writeFlags{})
	targets, err := ops.LoadTargets(ctx, acc, onlyAuth, onlySigning)
	if err != nil {
		return nil, err
	}
	if a.interactive && !onlyAuth && !onlySigning && unloadedDiskCount(targets) > 1 {
		targets, err = a.chooseLoadTarget(ctx, acc.ID, targets)
		if err != nil {
			return nil, err
		}
	}
	res, err := ops.Load(ctx, targets, func(privPath string, keychain bool) error {
		if keychain {
			return a.keychain(privPath)
		}
		return a.loadKey(privPath)
	})
	if res != nil {
		for _, w := range res.Warnings {
			a.warnf("%s", w)
		}
		for _, k := range res.Loaded {
			name := ops.LoadKeyName(ctx, k.Key)
			switch {
			case k.AlreadyLoaded:
				a.successf("Already in your agent: %s %s", k.Purpose, name)
			case k.Keychain:
				a.successf("Loaded %s %s into your agent and kept its passphrase in your Keychain", k.Purpose, name)
			default:
				a.successf("Loaded %s %s into your agent", k.Purpose, name)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return &ops.Result{Message: res.Message}, nil
}

func unloadedDiskCount(targets []ops.LoadTarget) int {
	n := 0
	for _, t := range targets {
		if t.Protection != keys.AgentOnly && !t.Loaded {
			n++
		}
	}
	return n
}

func (a *app) chooseLoadTarget(ctx ops.Context, id string, targets []ops.LoadTarget) ([]ops.LoadTarget, error) {
	choice := "both"
	opts := []huh.Option[string]{huh.NewOption("Both keys", "both")}
	for _, t := range targets {
		if t.Protection == keys.AgentOnly || t.Loaded {
			continue
		}
		label := fmt.Sprintf("Auth key (%s)", ops.LoadKeyName(ctx, t.Key))
		if t.Purpose == "signing key" {
			label = fmt.Sprintf("Signing key (%s)", ops.LoadKeyName(ctx, t.Key))
		}
		opts = append(opts, huh.NewOption(label, t.Purpose))
	}
	err := a.runForm(huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Which keys to load for " + id + "?").Options(opts...).Value(&choice),
	)))
	if err != nil {
		return nil, err
	}
	if choice == "both" {
		return targets, nil
	}
	for _, t := range targets {
		if t.Purpose == choice {
			return []ops.LoadTarget{t}, nil
		}
	}
	return targets, nil
}
