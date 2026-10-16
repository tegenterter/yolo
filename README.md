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

**9,759 known-vulnerable packages across 6 ecosystems**, each pinned to an exact
vulnerable version. Every ecosystem ships an idiomatic manifest plus an
`advisories.json` sidecar (package → version → advisory/CVE IDs).

| Ecosystem | Manifest | Packages | Distinct CVEs |
|-----------|----------|---------:|--------------:|
| npm       | `package.json`                     | 2,953 | 4,498 |
| PyPI      | `ecosystems/pypi/requirements.txt` | 1,614 | 6,391 |
| Maven     | `ecosystems/maven/pom.xml`         | 2,945 | 6,556 |
| Go        | `ecosystems/go/go.mod`             | 1,239 | 4,056 |
| crates.io | `ecosystems/cargo/Cargo.toml`      |   600 |   273 |
| RubyGems  | `ecosystems/rubygems/Gemfile`      |   408 | 1,050 |
| **Total** |                                    | **9,759** | |

The root `package.json` / `advisories.json` cover npm (7,717 advisories total).
Each pin is a real, still-published version known to be vulnerable: enumerated in
the advisory, or the highest registry version inside a vulnerable range. For PyPI,
RubyGems, crates.io and Go, pins are verified against the live registry / module
proxy; Maven pins use advisory-enumerated versions.

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
