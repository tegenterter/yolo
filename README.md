# yolo

A **security-research fixture**: a `package.json` pinned to a large set of
**known-vulnerable npm package versions**, for exercising software-composition-analysis
(SCA) tooling — `npm audit`, [osv-scanner](https://github.com/google/osv-scanner),
Snyk, Dependabot, Trivy, etc.

> This is **not** an application you run. It is a deliberately vulnerable dependency
> manifest. Every pin is a real, still-published package version that carries at least
> one disclosed CVE or GitHub/OSV advisory with an assigned weakness (CWE) class.

## Provenance

- Generated from the **OSV npm advisory database** (`osv-vulnerabilities.storage.googleapis.com/npm/all.zip`).
- Selection rule: non-malware advisories only, each with a `CVE-*` alias **or** a CWE
  class. Each package is pinned to a real, **still-published** version that is known
  vulnerable — either enumerated directly in the advisory, or the highest registry
  version falling inside a vulnerable range (`introduced → fixed`).
- `advisories.json` maps every pinned package → its version and the advisory/CVE IDs
  behind it.

## Contents

**11,433 known-vulnerable packages across 10 ecosystems**, each pinned to an exact
vulnerable version. Every ecosystem ships an idiomatic manifest, a lockfile, and an
`advisories.json` sidecar (package → version → advisory/CVE IDs).

| Ecosystem | Manifest | Lockfile | Packages | Distinct CVEs |
|-----------|----------|----------|---------:|--------------:|
| npm       | `package.json`                     | `package-lock.json`                 | 2,953 | 4,498 |
| Maven     | `ecosystems/maven/pom.xml`         | —                                   | 2,945 | 6,556 |
| PyPI      | `ecosystems/pypi/requirements.txt` | (pinned `==`)                       | 1,614 | 6,391 |
| Go        | `ecosystems/go/go.mod`             | —                                   | 1,239 | 4,056 |
| Packagist | `ecosystems/packagist/composer.json` | `ecosystems/packagist/composer.lock` | 961 | 5,533 |
| NuGet     | `ecosystems/nuget/packages.config` | `ecosystems/nuget/packages.lock.json` | 617 | 1,072 |
| crates.io | `ecosystems/cargo/Cargo.toml`      | `ecosystems/cargo/Cargo.lock`       |   600 |   273 |
| RubyGems  | `ecosystems/rubygems/Gemfile`      | `ecosystems/rubygems/Gemfile.lock`  |   408 | 1,050 |
| Hex       | `ecosystems/hex/mix.exs`           | `ecosystems/hex/mix.lock`           |    85 |   295 |
| Pub       | `ecosystems/pub/pubspec.yaml`      | `ecosystems/pub/pubspec.lock`       |    11 |    11 |
| **Total** |                                    |                                     | **11,433** | |

Each pin is a real, still-published version known to be vulnerable: enumerated in the
advisory, or the highest registry version inside a vulnerable range. PyPI, RubyGems,
crates.io, Go, NuGet, Packagist, Pub and Hex pins are verified against their live
registry / module proxy; Maven pins use advisory-enumerated versions.

### Lockfiles

Lockfiles are included so ecosystem-native scanners (`npm audit`, `bundler-audit`,
`composer audit`, etc.) and `osv-scanner` can read the repo with zero resolution
steps. They are **synthesized directly from the pinned versions** — flat (the
vulnerable packages are the direct dependencies), with no transitive resolution and
no network, install, or code execution. They carry package names and exact versions
(what SCA tools match on), not integrity hashes. Maven (`pom.xml`) and Go (`go.mod`)
are scanned directly; PyPI's `==`-pinned `requirements.txt` is its own lock.

## What was deliberately EXCLUDED

This fixture contains vulnerable-but-legitimate libraries only. It intentionally
**does not** include:

- OSV's `MAL-*` malicious-package namespace (typosquats, credential stealers,
  install-time payloads) — ~222k entries filtered out.
- Older malicious packages that were later unpublished from npm — they fail the
  registry-existence check and drop out.
- Anything whose advisory text describes it as malware / malicious code.

The distinction matters: *vulnerable* packages have bugs that only trigger when your
code uses them a certain way. *Malicious* packages attack the host during
`npm install` via lifecycle scripts, before any `import`. This fixture is the former.

## Safe usage

`.npmrc` in this directory sets `ignore-scripts=true`, so lifecycle scripts are
blocked even if you install. Still, treat this as untrusted:

**Scan without installing (recommended).** Resolve a lockfile without downloading
or executing any package (`--package-lock-only` writes the tree only; `--ignore-scripts`
blocks lifecycle hooks), then point a scanner at it:

```bash
npm install --package-lock-only --ignore-scripts --legacy-peer-deps
osv-scanner scan --lockfile=package-lock.json
# or:
npm audit
```

**If you must install, do it in a throwaway sandbox** (container/VM), never on a host
with real secrets, SSH keys, or cloud credentials present:

```bash
# inside a disposable container only
npm install --ignore-scripts --no-audit --no-fund
npm audit
```

**Scan every ecosystem at once** — `osv-scanner` walks the repo and reads all the
manifests (`requirements.txt`, `go.mod`, `Gemfile`, `Cargo.toml`, `pom.xml`, …)
without installing anything:

```bash
osv-scanner scan --recursive .
```

Do not deploy this. Do not install or import these packages in anything real.
