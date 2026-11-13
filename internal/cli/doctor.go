package cli

import (
	"fmt"
	"strings"

	"charm.land/huh/v2"
	"github.com/hononeko/doppel/internal/accounts"
	"github.com/hononeko/doppel/internal/doctor"
	"github.com/hononeko/doppel/internal/ui"
)

const doctorUsage = "doppel doctor [--fix] [--fix-remotes] [--json]"

type doctorFindingJSON struct {
	Severity string `json:"severity"`
	Area     string `json:"area"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

type doctorJSON struct {
	Findings []doctorFindingJSON `json:"findings"`
	Problems int                 `json:"problems"`
	Warnings int                 `json:"warnings"`
}

// cmdDoctor checks everything that could make Git use the wrong account,
// and says how to fix each problem. --fix redoes doppel's own files, and
// --fix-remotes switches mismatched repo remotes in bound folders.
func (a *app) cmdDoctor(args []string) int {
	fs := newFlagSet("doctor")
	var fix, fixRemotes, asJSON bool
	fs.BoolVar(&fix, "fix", false, "bring doppel's files up to date")
	fs.BoolVar(&fixRemotes, "fix-remotes", false, "switch mismatched repo remotes to match each account's protocol")
	fs.BoolVar(&asJSON, "json", false, "output findings as JSON")
	positional, code, ok := a.parseCommand(fs, args, doctorUsage)
	if !ok {
		return code
	}
	if len(positional) != 0 {
		return a.usageError(doctorUsage)
	}
	if fix {
		if err := a.lockWrites(); err != nil {
			return a.fail(err)
		}
	}
	list, err := accounts.Load(a.env)
	if err != nil {
		return a.fail(err)
	}
	findings := doctor.Check(doctor.Options{
		Env: a.env, Accounts: list, GitHub: a.github, Keychain: a.macKeychain(),
		Fix: fix, FixRemotes: fixRemotes, Cwd: a.cwd,
	})
	problems := doctor.Count(findings, doctor.Problem)
	warnings := doctor.Count(findings, doctor.Warning)
	if asJSON {
		out := make([]doctorFindingJSON, 0, len(findings))
		for _, f := range findings {
			out = append(out, doctorFindingJSON{
				Severity: f.Severity.String(),
				Area:     f.Area,
				Message:  f.Message,
				Fix:      f.Fix,
			})
		}
		if code := a.printJSON(doctorJSON{Findings: out, Problems: problems, Warnings: warnings}); code != 0 {
			return code
		}
		if problems > 0 {
			return 1
		}
		return 0
	}

	a.printFindings(findings)
	if a.interactive && !fixRemotes {
		if fixes := doctor.RemoteFixes(findings); len(fixes) > 0 {
			if err := a.promptRemoteFixes(fixes); err != nil {
				return a.fail(err)
			}
		}
	}
	if problems > 0 {
		return 1
	}
	return 0
}

func (a *app) promptRemoteFixes(fixes []*doctor.RemoteMismatch) error {
	title := fmt.Sprintf("Switch remote URLs in %s?", doctor.Plural(len(fixes), "repo"))
	if len(fixes) == 1 {
		title = fmt.Sprintf("Switch %s remotes to %s?", fixes[0].Dir, fixes[0].Target)
	}
	cmds := make([]string, 0, len(fixes))
	for _, m := range fixes {
		cmds = append(cmds, m.Command)
	}
	apply := false
	err := a.runForm(huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title(title).Description(strings.Join(cmds, "\n")).
			Affirmative("Yes").Negative("No").Value(&apply),
	)))
	if err != nil || !apply {
		if cancelled(err) {
			return nil
		}
		return err
	}
	for _, m := range fixes {
		if err := doctor.ApplyRemoteFix(m); err != nil {
			return err
		}
		a.successf("Switched %s remotes to %s", m.Dir, m.Target)
	}
	return nil
}

// printFindings shows doctor's findings under a heading for each area, each
// with its fix below it, then counts the problems and warnings.
func (a *app) printFindings(findings []doctor.Finding) {
	marks := map[doctor.Severity]string{
		doctor.OK:      ui.OK.Render("✓"),
		doctor.Note:    ui.Dim.Render("–"),
		doctor.Warning: ui.Warn.Render("⚠"),
		doctor.Problem: ui.Error.Render("✗"),
	}
	area := ""
	for _, f := range findings {
		if f.Area != area {
			area = f.Area
			a.printf("\n%s\n", ui.Title.Render(area))
		}
		a.printf("  %s %s\n", marks[f.Severity], f.Message)
		if f.Fix != "" {
			a.printf("    %s\n", ui.Dim.Render("↳ "+f.Fix))
		}
	}

	a.printf("\n")
	problems, warnings := doctor.Count(findings, doctor.Problem), doctor.Count(findings, doctor.Warning)
	if problems == 0 && warnings == 0 {
		a.successf("No problems found")
		return
	}
	a.printf("%s, %s\n", doctor.Plural(problems, "problem"), doctor.Plural(warnings, "warning"))
}
