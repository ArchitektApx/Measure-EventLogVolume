# Hardening the repository

The release workflow publishes to the PowerShell Gallery, where a version number can never
be reused and consumers install without reviewing what they get. That makes push access to
your default branch equivalent to push access to everyone's machines. The settings below
close that path. None of them are on by default.

Everything here is configured on GitHub, not in this repository, so it does not survive
"Use this template" and has to be redone per repo. Do it before the first tag.

## 1. Add the publishing secret

Settings > Secrets and variables > Actions > New repository secret.

Name it `PSGALLERY_API_KEY`. The value is a PowerShell Gallery API key scoped to push for
this module only.

Create the key at [powershellgallery.com](https://www.powershellgallery.com) > your account >
API Keys. Scope it to the single package glob (e.g. `YourModule`) rather than `*`, and give
it an expiry. A leaked wildcard key lets an attacker push a new version of every module you
own.

```bash
gh secret set PSGALLERY_API_KEY --repo <owner>/<repo>
```

## 2. Lock down the default branch

This is the step that matters most. Create a branch ruleset (Settings > Rules > Rulesets >
New branch ruleset) targeting **Default branch**, with enforcement **Active** and an empty
**Bypass list**:

| Rule                                  | What it does                            | Why it matters here                                                             |
| ------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------- |
| **Restrict deletions**                | The branch cannot be deleted            | Stops a history reset from being laundered through a delete/recreate            |
| **Block force pushes**                | No non-fast-forward pushes              | The commit CI approved stays the commit that gets tagged                        |
| **Require signed commits**            | Every commit needs a verified signature | An attacker with a stolen token can still push, but cannot forge commits as you |
| **Require a pull request**            | No direct pushes, even yours            | Every change gets a diff view and a CI run before it lands                      |
| **Require status checks to pass**     | The CI matrix must be green             | The published artifact is the one that passed on every target host              |
| **Require branches to be up to date** | Re-run CI after a base change           | Catches changes that merge cleanly but break at runtime                         |

Inside the pull request rule, two sub-options are worth switching on: **Require conversation
resolution before merging**, and **Require an additional approval for changes with unknown
authorship** (which catches commits whose author does not match a known contributor).

Leave **Required approvals** at `0` if you are the only maintainer. You still get the PR, the
diff, and the CI gate, without needing a second account to approve your own work. Raise it to
`1` the moment anyone else has write access.

> [!CAUTION]
> The bypass list is where this usually goes wrong. If you leave yourself on it, anyone who
> compromises your account walks straight past every rule above. Keep it empty and accept the
> friction.

The required status check contexts are the CI job names, which depend on your
`ModuleTargetPlatform`:

| Preset              | Contexts to require                                                     |
| ------------------- | ----------------------------------------------------------------------- |
| `PowerShell5.1`     | `test (win / WinPS 5.1)`                                                |
| `PowerShell7`       | `test (win / pwsh 7)`, `test (linux / pwsh 7)`, `test (macos / pwsh 7)` |
| `PowerShell5.1And7` | all four of the above                                                   |

They only appear in the picker after the workflow has run at least once, so push a branch
and open a PR first. Select **GitHub Actions** as the source so a check cannot be spoofed by
a third-party app posting the same name.

Or apply the whole ruleset in one command. This one uses the `PowerShell5.1And7` contexts:

```bash
gh api --method POST repos/<owner>/<repo>/rulesets --input - <<'JSON'
{
  "name": "default-branch-protection",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_signatures" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "required_review_thread_resolution": true,
        "require_extra_approval_for_unattributed_changes": true,
        "require_code_owner_review": false,
        "dismiss_stale_reviews_on_push": false,
        "require_last_push_approval": false,
        "required_reviewers": [],
        "allowed_merge_methods": ["merge", "squash", "rebase"]
    } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "test (win / WinPS 5.1)",   "integration_id": 15368 },
          { "context": "test (win / pwsh 7)",      "integration_id": 15368 },
          { "context": "test (linux / pwsh 7)",    "integration_id": 15368 },
          { "context": "test (macos / pwsh 7)",    "integration_id": 15368 }
        ]
    } }
  ]
}
JSON
```

`integration_id` 15368 is the GitHub Actions app, which is what pins each check to Actions.
Trim the `required_status_checks` list to match your platform preset.

## 3. Make release tags immutable

A second ruleset, this time targeting **Tags** with the pattern `refs/tags/v*.*.*`, again
with an empty bypass list and these three rules: **Restrict deletions**, **Block force
pushes**, and **Restrict updates**.

A published Gallery version is permanent, so the tag it came from must be too. Without this,
`v1.2.0` can be moved to point at different code after the fact, and the GitHub release then
misrepresents what was shipped. `release.yml` already refuses to publish when the tag does
not match the manifest version; this makes the tag itself unable to move.

```bash
gh api --method POST repos/<owner>/<repo>/rulesets --input - <<'JSON'
{
  "name": "release-tag-protection",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["refs/tags/v*.*.*"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "update" }
  ]
}
JSON
```

## 4. Restrict what Actions can do

Settings > Actions > General > Workflow permissions:

- **Read repository contents and packages permissions** (the restrictive default)
- **Uncheck** "Allow GitHub Actions to create and approve pull requests"

`release.yml` asks for `contents: write` explicitly in its own `permissions:` block, because
it has to create the GitHub release. Everything else runs read-only. Setting the default this
way means a workflow that never declares `permissions:` cannot quietly write to the repo.

```bash
gh api --method PUT repos/<owner>/<repo>/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

## 5. Turn on the scanners

Settings > Advanced Security (free on public repositories):

| Setting               | What it does                          |
| --------------------- | ------------------------------------- |
| **Secret scanning**   | Flags credentials already committed   |
| **Push protection**   | Blocks the push that would commit one |
| **Dependabot alerts** | Notifies on vulnerable dependencies   |

Push protection is the most useful of the three. It blocks a pasted API key before it reaches
the remote, while rotating the key is still the entire cleanup.

```bash
gh api --method PATCH repos/<owner>/<repo> \
  -F security_and_analysis[secret_scanning][status]=enabled \
  -F security_and_analysis[secret_scanning_push_protection][status]=enabled
gh api --method PUT repos/<owner>/<repo>/vulnerability-alerts
```

`.github/dependabot.yml` in this template watches GitHub Actions versions only, which is the
supply-chain surface that matters for a PowerShell module. A compromised or moved action tag
runs with your `PSGALLERY_API_KEY` in scope. There is no lockfile here for Dependabot to
track, so nothing else needs watching.

## 6. Sign your commits

`Require signed commits` above means nothing until your own commits are signed. SSH signing
is the least painful route if you already push over SSH:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the same public key again at GitHub > Settings > SSH and GPG keys, this time as a
**Signing key**.

> [!IMPORTANT]
> An authentication key does not count as a signing key, and this trips up almost everyone.
> Add the same public key a second time with the Signing key type.

Verify with `git log --show-signature -1`, or look for the "Verified" badge on GitHub.

## Checklist

- [ ] `PSGALLERY_API_KEY` set, scoped to this module, with an expiry
- [ ] Default-branch ruleset active, **bypass list empty**
- [ ] Status check contexts match your platform preset
- [ ] Tag ruleset on `refs/tags/v*.*.*` active
- [ ] Actions default permissions read-only, PR creation off
- [ ] Secret scanning + push protection on
- [ ] Local commit signing configured and verified