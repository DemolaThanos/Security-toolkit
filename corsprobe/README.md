# corsprobe

Authorised CORS checks. You give it URLs. It sends a small set of GET requests with a crafted `Origin`, plus one OPTIONS preflight, and reads `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, and the preflight allow lists.

## Disclaimer

Use it only on systems you own or have written permission to test. Unauthorised scanning is illegal in a lot of places. The command refuses to run without `--i-am-authorized` or `CORSPROBE_AUTHORIZED=1`. That flag is an acknowledgement, not a permission slip. It does not turn the other limits off.

corsprobe does not send a request body, cookies, or an `Authorization` value. It does not send PUT, DELETE, or POST. The preflight asks whether those methods and headers would be allowed; it does not call them. Redirects to a different host are not followed unless you pass `--follow-off-host`, and a redirect from a public address to a private one is refused either way. Link-local and other non-routable addresses are refused, including the cloud metadata address. TLS is verified. A private or loopback address you named is allowed, so a staging host on RFC1918 can be checked.

This is not authrecon. authrecon records security headers, the TLS handshake, and optional TCP connects. corsprobe only looks at CORS.

## Install

```bash
pip install .
```

Python 3.11 or newer. No third-party packages.

## Usage

```bash
corsprobe scan https://app.example --i-am-authorized
corsprobe scan https://app.example --i-am-authorized --trusted example.com --fail-on high
corsprobe scan --urls urls.txt --i-am-authorized --format sarif --output corsprobe.sarif
```

Pass URLs as arguments, as a file, or both. `--urls -` reads stdin. Blank lines and lines that start with `#` are ignored, and a repeated URL is checked once. `examples/urls.txt` is a sample of documentation names.

`--trusted` is the hostname the application means to allow, such as `example.com`. Prefix, suffix, and unescaped-dot probes are sent for that host and for the target host. Without it, those probes use the target host only.

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings, `2` bad input, a refused run, or a target that could not be probed. Findings below the threshold are still printed. A connection failure is not a finding. The report for the targets that finished is still written, and the command exits `2`.

`--timeout` (default 5 seconds) applies to each connection. Requests share one rate limit (default 4 per second) across the worker pool (default 4, maximum 8). `--rate 0` disables the pause. Each target is probed one request at a time. `CORSPROBE_LOG_FORMAT=json` writes one JSON object per log line. The User-Agent is `corsprobe/<version>`.

```yaml
- run: pip install ./corsprobe
- run: corsprobe scan https://staging.example --i-am-authorized --format sarif --output corsprobe.sarif --fail-on high
```

## What it sends

For `https://app.example/api` and `--trusted example.com`, the Origin values are:

| Probe | Origin |
| --- | --- |
| arbitrary reflection | `https://corsprobe.invalid` |
| null origin | `null` |
| http on an https site | `http://app.example` |
| prefix | `https://app.example.corsprobe.invalid` and `https://example.com.corsprobe.invalid` |
| suffix | `https://notapp.example` and `https://notexample.com` |
| unescaped dot | `https://appxexample` and `https://examplexcom` |
| any subdomain | `https://corsprobe.app.example` and `https://corsprobe.example.com` |

The dot probe replaces the first `.` with `x`. A non-default port is kept on the http and subdomain origins. The preflight is one OPTIONS to the same URL with `Origin: https://corsprobe.invalid`, `Access-Control-Request-Method: DELETE`, and `Access-Control-Request-Headers: X-Corsprobe-Canary, Authorization`. `--no-preflight` skips it. Every request also sends `Cache-Control: no-cache`.

If the arbitrary origin is reflected, the narrower probes are not reported again. `Access-Control-Allow-Origin: *` is the wildcard rule, not reflection.

## What it reports

`Access-Control-Allow-Credentials: true` on the same response raises the severity by one step. `True` does not count. Browsers only accept the lowercase token. Critical stays critical.

| Rule | Base | With credentials | What it catches |
| --- | --- | --- | --- |
| `origin-reflection` | high | critical | an arbitrary origin is copied into `Access-Control-Allow-Origin` |
| `null-origin` | high | critical | the null origin is allowed |
| `prefix-bypass` | high | critical | a trusted host matches as a prefix of another origin |
| `suffix-bypass` | high | critical | a trusted host matches as a suffix without a dot before it |
| `unescaped-dot` | high | critical | the host matches the way an unescaped `.` in a regular expression would |
| `any-subdomain` | medium | high | any subdomain of the host is allowed |
| `http-origin` | medium | high | an https site trusts the same host over http |
| `wildcard` | low | | `Access-Control-Allow-Origin` is `*` |
| `wildcard-credentials` | medium | | `*` is combined with credentials. Browsers ignore this pair |
| `preflight-methods` | low | medium | a preflight for an open origin allows `*`, PUT, DELETE, PATCH, TRACE, or CONNECT |
| `preflight-headers` | low | medium | that preflight allows `*`, `Authorization`, or the canary header |

`table` is the default. `json` includes findings and probe errors. `sarif` is 2.1.0. Each result has `partialFingerprints.primaryLocationLineHash`. Rules that did not fire are still listed. A reflected origin with credentials looks like this:

```
severity  rule               target                   message
--------  -----------------  -----------------------  ----------------------------------------------------------
critical  origin-reflection  https://app.example/api  reflected https://corsprobe.invalid and allows credentials
1 finding
```

## Limitations

The allow-origin value has to match the origin that was sent. That is the comparison browsers make. Two `Access-Control-Allow-Origin` headers are ignored, because browsers reject them too.

No cookies are sent, so a policy that only appears on an authenticated request is invisible. The dot probe uses one stand-in character, `x`, not every character a regex would accept. There is no public-suffix list. Any-subdomain uses the host you passed to `--trusted`, and the target host.

A shared cache that ignores `Cache-Control: no-cache` could still store a response. The tool does not try to poison one.

A bad certificate is a probe error, not a CORS result. Verification is not disabled. This is not a browser and it does not run JavaScript.

## License

MIT
