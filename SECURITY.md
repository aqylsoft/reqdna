# Security Policy

## Supported versions

| Version | Security fixes |
|---------|---------------|
| 0.1.x   | ✅ Yes         |

Older versions (if any) receive no security updates.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please use GitHub's private vulnerability reporting:

1. Go to https://github.com/aqylsoft/reqdna/security/advisories/new
2. Fill in the description, affected versions, and reproduction steps.
3. Submit — only the maintainers will see it.

Alternatively, email **security@aqylsoft.com** with:
- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested fix (optional)

Encrypt sensitive reports with the PGP key published at
https://github.com/aqylsoft.gpg.

## Response timeline

| Stage                         | Target     |
|-------------------------------|------------|
| Acknowledgement               | 2 business days |
| Triage and severity assessment| 5 business days |
| Patch + private advisory draft| 14 days (critical: 7 days) |
| Coordinated public disclosure | 90 days after report (or sooner if a patch is ready) |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):
you will receive a heads-up before the fix is published so you can update your
dependency before the vulnerability is public.

## Scope

Areas of particular concern for this library:

- **JA3 parsing** (`ja3.go`): malformed `tls.ClientHelloInfo` leading to panic or
  incorrect fingerprint
- **IP hashing** (`ip.go`): hash collisions or salt-bypass that could allow
  identity spoofing
- **Header analysis** (`headers.go`): input that causes excessive allocation or
  CPU usage (ReDoS-equivalent)
- **BotScore manipulation**: crafted requests that reliably score 0.0 despite
  being automated traffic

Out of scope: issues in the Go standard library, upstream CVEs in dependencies
(reqdna has no third-party dependencies).

## CVE assignment

If the issue warrants a CVE, the maintainers will request one through
[GitHub's CVE numbering authority](https://github.blog/2022-02-22-github-cna/)
and include it in the security advisory before public disclosure.
