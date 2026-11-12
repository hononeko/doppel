package ops

import (
	"errors"
	"fmt"

	"github.com/hononeko/doppel/internal/accounts"
	"github.com/hononeko/doppel/internal/keys"
)

// LoadTarget is one of an account's keys to load into ssh-agent.
type LoadTarget struct {
	Key        keys.Ref // expanded
	Purpose    string   // "auth key", "signing key", or "auth and signing key"
	Protection keys.Protection
	Loaded     bool // already in ssh-agent
}

// LoadedKey is the outcome of loading one key into ssh-agent.
type LoadedKey struct {
	Key           keys.Ref // expanded
	Purpose       string
	AlreadyLoaded bool
	Keychain      bool
}

// LoadResult is what Load did.
type LoadResult struct {
	Loaded   []LoadedKey
	Warnings []string
	Message  string
}

// LoadTargets resolves the keys to load for acc and checks their status on
// disk and in ssh-agent.
func LoadTargets(ctx Context, acc *accounts.Account, onlyAuth, onlySigning bool) ([]LoadTarget, error) {
	if onlyAuth && onlySigning {
		return nil, errors.New("use either --auth or --signing")
	}
	auth, signing := acc.AuthKey.Map(ctx.Env.Expand), acc.SigningKey.Map(ctx.Env.Expand)
	switch {
	case onlyAuth && auth == "":
		if acc.Protocol == accounts.ProtocolHTTPS {
			return nil, fmt.Errorf("account %s uses HTTPS and has no auth key", acc.ID)
		}
		return nil, fmt.Errorf("account %s has no auth key", acc.ID)
	case onlySigning && signing == "":
		return nil, fmt.Errorf("account %s has no signing key", acc.ID)
	case !onlyAuth && !onlySigning && auth == "" && signing == "":
		return nil, fmt.Errorf("account %s has no keys to load", acc.ID)
	}

	same := auth.SameKey(signing)
	var targets []LoadTarget
	if auth != "" && !onlySigning {
		purpose := "auth key"
		if same && !onlyAuth {
			purpose = "auth and signing key"
		}
		targets = append(targets, LoadTarget{Key: auth, Purpose: purpose})
	}
	if signing != "" && !onlyAuth && (!same || len(targets) == 0) {
		targets = append(targets, LoadTarget{Key: signing, Purpose: "signing key"})
	}

	allAgentOnly := true
	for i := range targets {
		prot := keys.CheckProtection(targets[i].Key)
		if prot == keys.Unknown {
			return nil, fmt.Errorf("%s %s doesn't exist", targets[i].Purpose, targets[i].Key.Map(ctx.Env.Shorten).Display())
		}
		targets[i].Protection = prot
		if prot != keys.AgentOnly {
			allAgentOnly = false
		}
	}

	if !keys.HasSSHAdd() {
		return nil, errors.New("ssh-add isn't installed")
	}
	if !keys.AgentRunning() {
		return nil, errors.New(`no ssh-agent is running; start one with: eval "$(ssh-agent)"`)
	}

	for i := range targets {
		targets[i].Loaded, _ = keys.InAgent(targets[i].Key)
	}
	if allAgentOnly {
		for _, t := range targets {
			if !t.Loaded {
				return nil, fmt.Errorf("%s %s lives in an agent and has no private key file on disk; unlock it in your agent",
					t.Purpose, t.Key.Map(ctx.Env.Shorten).Display())
			}
		}
	}
	return targets, nil
}

// Load loads targets into ssh-agent using add, skipping keys that are already
// in the agent. On an error, the result still lists keys loaded before it.
func Load(ctx Context, targets []LoadTarget, add func(privPath string, keychain bool) error) (*LoadResult, error) {
	res := &LoadResult{}
	for _, t := range targets {
		if t.Protection == keys.AgentOnly {
			if t.Loaded {
				res.Loaded = append(res.Loaded, LoadedKey{Key: t.Key, Purpose: t.Purpose, AlreadyLoaded: true})
			} else {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s lives in an agent and has no private key file on disk; unlock it in your agent",
					t.Purpose, t.Key.Map(ctx.Env.Shorten).Display()))
			}
			continue
		}
		if t.Loaded {
			res.Loaded = append(res.Loaded, LoadedKey{Key: t.Key, Purpose: t.Purpose, AlreadyLoaded: true})
			continue
		}
		useKeychain := ctx.keychain() && t.Protection == keys.Encrypted
		if err := add(t.Key.PrivatePath(), useKeychain); err != nil {
			return res, err
		}
		res.Loaded = append(res.Loaded, LoadedKey{Key: t.Key, Purpose: t.Purpose, Keychain: useKeychain})
	}
	res.Message = loadMessage(ctx, res.Loaded)
	return res, nil
}

// LoadKeyName names a key's private half for load messages, "~/"-shortened.
func LoadKeyName(ctx Context, key keys.Ref) string {
	if priv := key.PrivatePath(); priv != "" {
		return ctx.Env.Shorten(priv)
	}
	return key.Map(ctx.Env.Shorten).Display()
}

func loadMessage(ctx Context, loaded []LoadedKey) string {
	if len(loaded) == 0 {
		return "No keys loaded"
	}
	if len(loaded) == 1 {
		k := loaded[0]
		name := LoadKeyName(ctx, k.Key)
		if k.AlreadyLoaded {
			return fmt.Sprintf("Already in agent: %s %s", k.Purpose, name)
		}
		return fmt.Sprintf("Loaded %s %s into agent", k.Purpose, name)
	}
	for _, k := range loaded {
		if !k.AlreadyLoaded {
			return "Loaded keys into agent"
		}
	}
	return "Keys are already in agent"
}
