# Security Policy

## What this project is

This is a local-first, single-user Flask prototype. It is not a hosted service,
it has no multi-tenant isolation, and it has not undergone a third-party security
audit. Treat findings against it accordingly — see the "Threat Model" section of
`README.md` for what it does and does not defend against before filing a report.

## Supported versions

There is no long-term support branch and no version numbering scheme yet. Only
the current `main` branch is supported. If you are running an older checkout,
update to the latest commit before reporting an issue — it may already be fixed.

## Reporting a vulnerability

Report privately by emailing **emir@lovie.co**. Do not open a public GitHub
issue for a security report, and in particular:

**Do not open a public issue for anything involving a data leak, an
unredacted export, a privacy-finding bypass, or a way to make the app treat
sensitive text as safe when it is not.** Documents processed by this tool are
often real legal filings; a public issue describing how to leak them is itself
a leak. Email the contact above instead.

Please include in your report:

- A description of the issue and its impact (what data or behavior is exposed,
  and under what conditions).
- Steps to reproduce, ideally against a synthetic document — do not attach real
  client or case files to a report.
- The commit hash or version you tested against.
- Whether the issue requires local access to the machine running the app, or is
  reachable over the network (see the threat model: this app binds to
  `127.0.0.1` by default and assumes anyone who can reach the port is trusted;
  a report showing that assumption is wrong for a specific configuration is
  still worth sending).

You should expect an acknowledgment within a reasonable time given this is a
single-maintainer prototype, not a funded security team. There is no bug
bounty.

## Known limitations (not yet fixed)

These are disclosed deliberately rather than left for a reporter to find.

- **`extract_zip_text` trusts the archive-declared member size** (`ZipInfo.file_size`)
  in one remaining path, which a crafted zip can understate.
- **`reviewer_note` is not sanitised at write time.** It is escaped at render, so it is
  not an injection vector today, but it is unvalidated free text.
