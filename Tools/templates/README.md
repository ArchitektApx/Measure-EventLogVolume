# {{ModuleName}}

[![Version](https://img.shields.io/badge/Version-{{SemVer}}-green.svg)]({{ProjectUri}})
[![CI]({{ProjectUri}}/actions/workflows/ci.yml/badge.svg)]({{ProjectUri}}/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]({{ProjectUri}}/blob/{{DefaultBranch}}/LICENSE)

{{ModuleDescription}}

## Installation

```powershell
Install-Module -Name {{ModuleName}} -Scope CurrentUser
```

## Usage

```powershell
Import-Module {{ModuleName}}

# Your first example goes here.
```

## Development

{{Requirements}}

```powershell
./tasks.ps1 install_dev_requirements   # once per host, per PowerShell edition
./tasks.ps1 build                      # Source/ -> Dist/
./tasks.ps1 test
./tasks.ps1 lint
./tasks.ps1 coverage
```

See [Tools/README.md](Tools/README.md) for the full tool reference.

### Project layout

```text
.
├── build.psd1           # ModuleBuilder build config (manifest path, output, SemVer)
├── module.psd1          # Module metadata consumed by the tooling
├── tasks.ps1            # Task runner
├── Source/
│   ├── {{ModuleName}}.psd1
│   ├── {{ModuleName}}.psm1
│   ├── Enum/            # One .ps1 per enum
│   ├── Classes/         # One .ps1 per class
│   ├── Private/         # Internal helpers, not exported
│   └── Public/          # One .ps1 per exported function
├── Tests/               # Pester tests, run against the BUILT module
├── Tools/               # Build, test, lint, coverage, release tooling
├── Docs/HARDENING.md    # GitHub settings to set before publishing
└── Dist/                # Build output (gitignored)
```

Everything in `Tools/` imports the **built** module from `Dist/`, the same artifact a user
installs, so `build` has to run before `test` or `coverage`.

## Releasing

### 1. Prepare the release on a branch

```powershell
./tasks.ps1 prepare_release 1.1.0
```

This gates on lint/build/test, promotes the `[Unreleased]` changelog section to the new
version, stamps the version into `README.md` and `build.psd1`, rebuilds, and verifies the
built manifest carries the new version.

Review the diff, commit the stamped files, push the branch, and open a PR against `{{DefaultBranch}}`.

### 2. Merge, then tag `{{DefaultBranch}}`

Tagging is what triggers the release, and the tag has to sit on the merged commit. Pull
`{{DefaultBranch}}` first, otherwise you tag whatever you had locally:

```bash
git checkout {{DefaultBranch}}
git pull origin {{DefaultBranch}}
git tag v1.1.0
git push origin v1.1.0
```

> [!IMPORTANT]
> The tag must match the `ModuleVersion` in the built manifest, and `v1.1.0` must point at a
> commit that is on `{{DefaultBranch}}`. The workflow checks both and fails the release otherwise.

Pushing the tag runs `release.yml`: it re-runs the full CI matrix, publishes to the PowerShell
Gallery, and creates a GitHub release whose body is the `1.1.0` section of `CHANGELOG.md`.

Watch it under the repository's **Actions** tab. If it fails before publishing, delete the tag,
fix the problem, and tag again:

```bash
git push origin :refs/tags/v1.1.0   # delete the remote tag
git tag -d v1.1.0                   # delete it locally
```

> [!CAUTION]
> Only do that for a tag that never published. A version that reached the PowerShell Gallery
> can never be reused or replaced, so a bad publish needs a new patch version instead.

Publishing needs a repository secret `PSGALLERY_API_KEY`.

> [!CAUTION]
> Before the first tag, work through [Docs/HARDENING.md](Docs/HARDENING.md). Publishing to the
> Gallery means push access to this branch is push access to everyone who installs
> {{ModuleName}}. That guide covers the branch and tag rulesets, Actions permissions, secret
> scanning, and commit signing. None of it is on by default.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) - Copyright (c) {{Year}} {{CompanyName}}
