package ops_test

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/hononeko/doppel/internal/accounts"
	"github.com/hononeko/doppel/internal/keys"
	"github.com/hononeko/doppel/internal/ops"
)

func TestLoadTargetsAndLoad(t *testing.T) {
	s, ctx, _ := newContext(t, nil)
	authKey := s.Key("id_work", "jane@acme.com", "pw")
	signKey := s.Key("id_work_signing", "jane@acme.com", "pw2")
	s.FakeAgent(authKey) // auth is already loaded; signing is not

	acc := &accounts.Account{
		ID:         "work",
		Email:      "jane@acme.com",
		Protocol:   accounts.ProtocolSSH,
		AuthKey:    "~/.ssh/id_work",
		SigningKey: "~/.ssh/id_work_signing.pub",
	}

	targets, err := ops.LoadTargets(ctx, acc, false, false)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %+v, want 2", targets)
	}
	if !targets[0].Loaded || targets[1].Loaded {
		t.Errorf("loaded flags = (%v, %v), want (true, false)", targets[0].Loaded, targets[1].Loaded)
	}

	var added []string
	res, err := ops.Load(ctx, targets, func(privPath string, keychain bool) error {
		added = append(added, privPath)
		if keychain {
			t.Error("expected keychain=false on Linux/default ctx")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(added, []string{signKey}) {
		t.Errorf("added = %q, want [%s]", added, signKey)
	}
	if len(res.Loaded) != 2 || !res.Loaded[0].AlreadyLoaded || res.Loaded[1].AlreadyLoaded {
		t.Errorf("res.Loaded = %+v", res.Loaded)
	}

	// Same key for auth and signing deduplicates to one target.
	sameAcc := &accounts.Account{
		ID:         "personal",
		Email:      "jane@personal.dev",
		AuthKey:    "~/.ssh/id_work",
		SigningKey: "~/.ssh/id_work.pub",
	}
	sameTargets, err := ops.LoadTargets(ctx, sameAcc, false, false)
	if err != nil || len(sameTargets) != 1 || sameTargets[0].Purpose != "auth and signing key" {
		t.Fatalf("same key targets = %+v, %v", sameTargets, err)
	}

	// Missing key fails before touching the agent.
	missingAcc := &accounts.Account{ID: "bad", AuthKey: "~/.ssh/nope"}
	if _, err := ops.LoadTargets(ctx, missingAcc, false, false); err == nil || !strings.Contains(err.Error(), "doesn't exist") {
		t.Errorf("missing key err = %v", err)
	}

	// Agent-only key alone fails when not in agent.
	agentOnlyKey := s.Key("id_agent", "jane@acme.com", "")
	if err := os.Remove(agentOnlyKey); err != nil {
		t.Fatal(err)
	}
	agentAcc := &accounts.Account{ID: "agent", AuthKey: "~/.ssh/id_agent.pub"}
	if _, err := ops.LoadTargets(ctx, agentAcc, false, false); err == nil || !strings.Contains(err.Error(), "lives in an agent") {
		t.Errorf("agent-only err = %v", err)
	}

	// Agent-only key paired with an on-disk signing key warns & skips the agent key, loading the signing key.
	mixedAcc := &accounts.Account{
		ID:         "mixed",
		AuthKey:    "~/.ssh/id_agent.pub",
		SigningKey: "~/.ssh/id_work_signing.pub",
	}
	mixedTargets, err := ops.LoadTargets(ctx, mixedAcc, false, false)
	if err != nil {
		t.Fatalf("mixed LoadTargets: %v", err)
	}
	added = nil
	res, err = ops.Load(ctx, mixedTargets, func(privPath string, _ bool) error {
		added = append(added, privPath)
		return nil
	})
	if err != nil {
		t.Fatalf("mixed Load: %v", err)
	}
	if !slices.Equal(added, []string{signKey}) || len(res.Warnings) != 1 {
		t.Errorf("mixed Load: added=%q warnings=%q", added, res.Warnings)
	}

	// Keychain is used when ctx.Keychain returns true and key is Encrypted.
	ctx.Keychain = func() bool { return true }
	var keychained []string
	_, err = ops.Load(ctx, []ops.LoadTarget{{
		Key:        keys.Ref(signKey),
		Purpose:    "signing key",
		Protection: keys.Encrypted,
	}}, func(privPath string, keychain bool) error {
		if !keychain {
			t.Error("expected keychain=true")
		}
		keychained = append(keychained, privPath)
		return nil
	})
	if err != nil || !slices.Equal(keychained, []string{signKey}) {
		t.Errorf("keychain Load: %q, %v", keychained, err)
	}
}

func TestLoadEdgeAndErrorCases(t *testing.T) {
	s, ctx, _ := newContext(t, nil)
	authKey := s.Key("id_work", "jane@acme.com", "pw")
	signKey := s.Key("id_work_signing", "jane@acme.com", "pw2")

	bothAcc := &accounts.Account{
		ID:         "work",
		Protocol:   accounts.ProtocolSSH,
		AuthKey:    "~/.ssh/id_work",
		SigningKey: "~/.ssh/id_work_signing.pub",
	}
	noAuthSSH := &accounts.Account{ID: "ssh-noauth", Protocol: accounts.ProtocolSSH, SigningKey: "~/.ssh/id_work_signing"}
	noAuthHTTPS := &accounts.Account{ID: "https-noauth", Protocol: accounts.ProtocolHTTPS, SigningKey: "~/.ssh/id_work_signing"}
	noSign := &accounts.Account{ID: "nosign", Protocol: accounts.ProtocolSSH, AuthKey: "~/.ssh/id_work"}
	emptyAcc := &accounts.Account{ID: "empty", Protocol: accounts.ProtocolSSH}

	// Parameter and missing-configuration errors before agent check.
	if _, err := ops.LoadTargets(ctx, bothAcc, true, true); err == nil || !strings.Contains(err.Error(), "either --auth or --signing") {
		t.Errorf("both flags err = %v", err)
	}
	if _, err := ops.LoadTargets(ctx, noAuthSSH, true, false); err == nil || !strings.Contains(err.Error(), "has no auth key") {
		t.Errorf("ssh no auth err = %v", err)
	}
	if _, err := ops.LoadTargets(ctx, noAuthHTTPS, true, false); err == nil || !strings.Contains(err.Error(), "uses HTTPS") {
		t.Errorf("https no auth err = %v", err)
	}
	if _, err := ops.LoadTargets(ctx, noSign, false, true); err == nil || !strings.Contains(err.Error(), "has no signing key") {
		t.Errorf("no signing err = %v", err)
	}
	if _, err := ops.LoadTargets(ctx, emptyAcc, false, false); err == nil || !strings.Contains(err.Error(), "no keys to load") {
		t.Errorf("empty err = %v", err)
	}
	// Agent not running error.
	if _, err := ops.LoadTargets(ctx, bothAcc, false, false); err == nil || !strings.Contains(err.Error(), "no ssh-agent") {
		t.Errorf("no agent err = %v", err)
	}

	// Filtering with onlyAuth / onlySigning on an account with both keys.
	s.FakeAgent(authKey, signKey)
	authTargets, err := ops.LoadTargets(ctx, bothAcc, true, false)
	if err != nil || len(authTargets) != 1 || authTargets[0].Purpose != "auth key" {
		t.Fatalf("onlyAuth targets = %+v, %v", authTargets, err)
	}
	signTargets, err := ops.LoadTargets(ctx, bothAcc, false, true)
	if err != nil || len(signTargets) != 1 || signTargets[0].Purpose != "signing key" {
		t.Fatalf("onlySigning targets = %+v, %v", signTargets, err)
	}

	// Message variants for already-loaded keys (1 vs >1, mixed vs all loaded, and 0 loaded).
	res, err := ops.Load(ctx, authTargets, nil)
	if err != nil || !strings.HasPrefix(res.Message, "Already in agent:") {
		t.Errorf("single already loaded: %+v, %v", res, err)
	}
	res, err = ops.Load(ctx, []ops.LoadTarget{authTargets[0], signTargets[0]}, nil)
	if err != nil || res.Message != "Keys are already in agent" {
		t.Errorf("multiple already loaded: %+v, %v", res, err)
	}

	// AgentOnly key that IS in the agent counts as AlreadyLoaded (and mixed 0-loaded warns -> "No keys loaded").
	agentKey := s.Key("id_agent", "jane@acme.com", "")
	if err := os.Remove(agentKey); err != nil {
		t.Fatal(err)
	}
	s.FakeAgent(agentKey)
	res, err = ops.Load(ctx, []ops.LoadTarget{{
		Key:        keys.Ref(agentKey + ".pub"),
		Purpose:    "auth key",
		Protection: keys.AgentOnly,
		Loaded:     true,
	}}, nil)
	if err != nil || len(res.Loaded) != 1 || !res.Loaded[0].AlreadyLoaded {
		t.Errorf("loaded agent-only: %+v, %v", res, err)
	}
	res, err = ops.Load(ctx, []ops.LoadTarget{{
		Key:        keys.Ref(agentKey + ".pub"),
		Purpose:    "auth key",
		Protection: keys.AgentOnly,
		Loaded:     false,
	}}, nil)
	if err != nil || res.Message != "No keys loaded" || len(res.Warnings) != 1 {
		t.Errorf("unloaded agent-only warning: %+v, %v", res, err)
	}

	// Error returned by add callback stops loading and surfaces partial results.
	boom := errors.New("bad passphrase")
	res, err = ops.Load(ctx, []ops.LoadTarget{
		{Key: keys.Ref(authKey), Purpose: "auth key", Protection: keys.Encrypted, Loaded: true},
		{Key: keys.Ref(signKey), Purpose: "signing key", Protection: keys.Encrypted, Loaded: false},
	}, func(string, bool) error { return boom })
	if !errors.Is(err, boom) || res == nil || len(res.Loaded) != 1 {
		t.Errorf("add error: res=%+v err=%v", res, err)
	}

	// LoadKeyName falls back to Display for inline literal keys.
	literal := keys.Ref("key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockInlineKeyForTesting")
	if got := ops.LoadKeyName(ctx, literal); !strings.HasPrefix(got, "inline ") {
		t.Errorf("LoadKeyName(literal) = %q", got)
	}

	// Missing ssh-add fails cleanly (use a fresh sandbox without fake ssh-add on PATH).
	s2, ctx2, _ := newContext(t, nil)
	s2.Key("id_no_ssh_add", "jane@acme.com", "")
	s2.OnlyCommands("ssh-keygen")
	noSSHAddAcc := &accounts.Account{ID: "no-ssh-add", Protocol: accounts.ProtocolSSH, AuthKey: "~/.ssh/id_no_ssh_add"}
	if _, err := ops.LoadTargets(ctx2, noSSHAddAcc, false, false); err == nil || !strings.Contains(err.Error(), "ssh-add isn't installed") {
		t.Errorf("missing ssh-add err = %v", err)
	}
}
