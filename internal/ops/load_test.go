package ops_test

import (
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
