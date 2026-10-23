# NothingPersonal (`nop`)

**Local AI agent privacy proxy — redact configured secrets from outbound HTTP/HTTPS requests.**

[![CI](https://github.com/Azayzel/NothingPersonal/actions/workflows/ci.yml/badge.svg)](https://github.com/Azayzel/NothingPersonal/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go)](https://go.dev/)

> *Nothing personal, kid.*

NothingPersonal is an open-source, zero-dependency **CLI privacy guard for AI coding agents**. Run a proxy-aware session of **Claude Code, OpenAI Codex CLI, Gemini CLI**, or another development tool through `nop` to inspect outgoing HTTP and HTTPS requests and replace configured email addresses, API keys, tokens, or other literal secrets before forwarding them.

- **Local-first:** HTTP/HTTPS interception and redaction happen on your machine; there is no hosted service.
- **Built for AI agents:** `nop run -- <agent>` starts an isolated proxy session and fails closed if setup fails.
- **Large-upload aware:** bounded-memory scanning, temporary disk spooling, gzip inspection, and configurable decoded-body limits.
- **Observable:** privacy-preserving audit logs identify redaction locations and destinations without printing original secret values.
- **Portable:** Go standard library only; builds for Linux, macOS, and Windows.

**Security scope:** This is a defense-in-depth HTTP(S) proxy, **not** a firewall, universal DLP solution, or zero-leak guarantee. Applications that bypass proxy settings can connect directly. Unsupported encodings, encrypted application payloads, and explicitly uninspected traffic are outside the redaction boundary. See [security and operational limitations](#security-and-operational-limitations).

## Quick start

Requires Go 1.23+.

```sh
go build -trimpath -o nop .
./nop run -- claude
```

On Windows PowerShell:

```powershell
go build -o nop.exe .
.\nop.exe run -- claude
```

By default, `nop run` discovers the Claude Code account email in `~/.claude.json`, creates a local CA in `~/.nop`, starts a **dedicated ephemeral loopback proxy**, configures proxy and certificate variables for its child, and exits with the child's exit status. **It fails closed:** if a protected session cannot be created, the agent does not launch.

Additional secrets can be passed directly (visible in process listings), or more safely via a private file:

```sh
chmod 600 ~/.nop/secrets.txt
./nop run -redact-file ~/.nop/secrets.txt -- codex
```

Each non-comment line in the file is treated as a literal secret. For manual operation in two terminals:

```sh
./nop -redact-file ~/.nop/secrets.txt
# in the agent terminal
eval "$(./nop -env)"
claude
```

PowerShell session setup: `./nop.exe -env -powershell | Invoke-Expression`.

## AI agent compatibility

`nop` is agent-agnostic: it relies on **standard HTTP proxy and TLS trust settings**, not integrations with any model provider. Compatibility depends on whether an agent and the tools it spawns respect those settings.

| Agent CLI | Example guarded session | Notes |
| --- | --- | --- |
| Claude Code | `./nop run -- claude` | Automatically discovers the signed-in Claude account email when available |
| OpenAI Codex CLI | `./nop run -redact-file ~/.nop/secrets.txt -- codex` | Add the specific secrets you want to protect |
| Gemini CLI | `./nop run -redact-file ~/.nop/secrets.txt -- gemini` | Add the specific secrets you want to protect |
| Other CLI agents / developer tools | `./nop run -redact-file ~/.nop/secrets.txt -- <command>` | Works only for proxied HTTP(S) traffic |

For a separate proxy process, use `nop -env` to print shell-scoped proxy and CA trust variables. **Test your particular CLI's TLS and proxy behavior before relying on it to protect sensitive data.**

## Coverage

| Traffic | Behavior |
| --- | --- |
| Plain HTTP requests through nop | URL, header, and body redaction |
| HTTPS CONNECT through nop | Local CA interception; upstream TLS verification |
| Literal / case-varied secrets | Redacted |
| URL query/path-escaped variants | Redacted |
| Large bodies | Inspected in bounded-memory chunks; sanitized bytes spooled to a private temporary file before forwarding |
| `Content-Encoding: gzip` | Decompressed, inspected, and recompressed |
| Other content encodings | **Blocked** (415) |
| Oversized decoded bodies | **Blocked** (413) |
| WebSocket/HTTP upgrades | **Blocked** (403); frames are not inspectable |
| Explicit `-no-mitm host1,host2` | **Uninspected tunnel**; prominently logged |
| Secrets found in destination authority | **Blocked**, not rewritten |
| Potentially signed modified bodies | **Blocked** when recognized |
| Go/Node/Python/curl applications ignoring proxy env | **Not protected** |

The default decoded request limit is **1,024 MiB** (`-max-body-mib`). Set a larger limit, or `0` for no limit, when you have enough free temporary disk space. The limit also applies after gzip decompression, reducing decompression-bomb risk. This is not an in-memory 1 GiB buffer: nop uses a 64 KiB scanning chunk and temporary disk files, updates the upstream `Content-Length`, and removes those files after the request.

Only the **redacted body** is written to temporary disk. Output logs include destination host and redaction locations/counts, not original secret values or URL paths.

## Configuration

```
-listen           loopback address (default 127.0.0.1:8787 for serve)
-redact           secret, repeatable
-redact-file      private file, one secret per line
-auto             detect Claude account email (default true)
-replacement      substitute text (default REDACTED)
-max-body-mib     maximum decoded body size (default 1024, 0 unlimited)
-no-mitm          explicit uninspected CONNECT tunnel host list
-upstream-proxy   optional HTTP(S) corporate upstream proxy URL
-ca-dir           local CA directory (default ~/.nop)
-quiet            suppress clean-request logs
-env              print session environment exports (without starting)
-powershell       use PowerShell syntax with -env
-version          print version
```

Set `NOP_UPSTREAM_CA=/path/to/corporate.pem` to add trusted upstream TLS roots. nop **does not** automatically use an ambient upstream proxy, avoiding accidental proxy loops. Set `-upstream-proxy` deliberately if required.

## Security and operational limitations

- **Proxy settings are advisory.** Environment-driven clients may bypass them, including when contacting loopback addresses. Strong egress control requires an OS/container firewall or network policy independently blocking direct connections.
- **TLS trust must be configured in each client.** `nop run` sets `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, and `SSL_CERT_FILE`; these are not universally honored and may replace other client-specific trust settings. Certificate-pinned clients will usually reject interception.
- **Not a DLP classifier.** This tool only detects known literal values and URL-escaped forms, not base64, split/reformatted values, archive members, encrypted data, or every JSON escape/serialization encoding. Raw bytes in binary bodies are scanned, but compressed/structured files inside those bodies aren't recursively decoded.
- **Only configured secrets are covered.** New credentials, tokens, names, or addresses must be added explicitly; automatic detection currently only reads Claude's account email.
- **Signed requests may break or be blocked.** Changes to a body invalidate hashes or signatures. gzip recompression can also change bytes without changing decoded content.
- **WebSocket frames are not scrubbed.** nop blocks upgrade requests rather than passing an uninspected stream. Use `-no-mitm` only when you explicitly accept that traffic is **not** protected.
- **Locally available CA key is sensitive.** `~/.nop/ca.key` is created with restricted permissions. Do not share it or commit it. If compromised, delete the pair and revoke its trust from your clients. nop never silently rotates invalid existing CA files.
- **Loopback-only listener.** Another local process can still use this unauthenticated proxy. Avoid treating it as an access-control boundary.
- **Disk/latency tradeoff.** Large request bodies are held on local disk until fully checked; ensure enough free disk space. Setting an unlimited size disables the decoded-body quota.
- **Platform support.** Go compiles for Windows, Linux, and macOS. Runtime behavior of individual AI CLIs and their trust stores must be verified in their actual environment.

## Test and build

```sh
go test ./...
go test -race ./...
go vet ./...
```

Releases should run cross-platform build checks; the included GitHub Actions workflow builds Linux, macOS, and Windows binaries for amd64 and arm64. No opaque prebuilt binary ZIP is required for the source repository.

## Why this exists

An agent can accidentally echo session-specific context into telemetry, headers, or requests. nop provides an inspectable, explicitly scoped defense-in-depth layer at the HTTP proxy boundary. It cannot prove that "nothing personal leaves the machine," so use it with that distinction in mind.

License: MIT.

## Contributing

Bug reports, reproducible privacy-bypass test cases, and pull requests are welcome. Please add regression tests for any redaction or interception change, run `go test -race ./...`, and avoid putting real secrets in issue reports or test fixtures.
