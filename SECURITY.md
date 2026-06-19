# Security Policy

**MCPGoat is *intentionally* vulnerable.** It is a security-training lab — the vulnerabilities are the product, not a
bug.

## Please do NOT report the built-in challenges

The 26 challenges (command injection, SSRF, SQL/NoSQL injection, prompt
injection, tool poisoning, XXE, deserialization, etc.) are deliberate and
documented in [`docs/SOLUTIONS.md`](docs/SOLUTIONS.md). Reports about these will
be closed as "by design."

## Do report *unintended* issues

If you find a flaw in the **harness itself** — the control panel, the scoreboard,
the build/CI, the Docker image, or anything that is *not* one of the documented
challenges — please report it privately:

- Open a [GitHub Security Advisory](../../security/advisories/new) (preferred), or
- Reach out via [LinkedIn](https://www.linkedin.com/in/sabyasachidhal/).

Please don't open a public issue for an unintended vulnerability until it's been
addressed.

## Run it safely

MCPGoat contains real RCE and SSRF. Use it for **authorized training only**: bind
it to `127.0.0.1`, ideally run it inside a container, and never expose it to a
network you don't control or point its tools at systems you aren't authorized to
test.
