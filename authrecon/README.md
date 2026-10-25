# authrecon

Authorised reconnaissance for one web host. It records response headers, the TLS handshake, and, only if you pass `--ports`, whether those ports accept a TCP connection.

Use it only on systems you own or have written permission to test. Unauthorised scanning is illegal in a lot of places. The command refuses to run without `--i-am-authorized` or `AUTHRECON_AUTHORIZED=1`. That flag is an acknowledgement, not a permission slip.

authrecon does not send exploit payloads, does not try credentials, and does not scan a port range wider than 32 ports. It opens the one host you named. A redirect to a different host is refused, including a public host, and so is a redirect into a private or link-local address. The TLS probe, the header request, and the optional port check share one DNS answer, and a redirect back to that host reuses it. Non-canonical IP spellings are rejected. `--i-am-authorized` does not turn those checks off.

A TLS certificate failure is a finding. The header request is not retried with verification disabled, so a failed certificate cannot supply headers or a redirect. The TLS probe may complete a second handshake without verifying the certificate only to record the negotiated protocol and cipher. That socket is closed before any HTTP is sent. The same is true of the TLS 1.0 and 1.1 probes. `AUTHRECON_LOG_FORMAT=json` writes one JSON object per log line.

## Install

```bash
pip install .
```

Python 3.11 or newer. No third-party packages.

## Usage

```bash
authrecon inspect https://app.example --i-am-authorized
authrecon inspect https://app.example --i-am-authorized --ports 80,443,8080 --format json
```

`--ports` is optional. Without it, the only connection is the URL you named. Banners are the first bytes the service sends; HTTP services usually send nothing until a request arrives, and the header check already covers that.

Exit codes: `0` nothing at or above `--fail-on` (default `medium`), `1` findings, `2` bad arguments or an unsafe target.

## What it reports

Header findings: HSTS, CSP, `X-Content-Type-Options`, clickjacking, `Referrer-Policy`, `Permissions-Policy`, COOP, cookie `Secure` / `HttpOnly` / `SameSite`, a `__Host-` cookie that is missing `Secure`, `Path=/`, or that sets `Domain`, and `Server` or `X-Powered-By` disclosure.

TLS findings: failure of a TLS 1.2+ handshake, certificate verification errors, certificates inside 30 days of expiry, acceptance of TLS 1.0 or 1.1, and a weak cipher negotiated by this client. It does not enumerate every cipher suite the server might still offer.

Observations, which do not fail the run: a Cloudflare, AWS WAF, Azure Front Door, or Akamai header when one is present, and whether a rate-limit header was on the response. A missing header is not proof that a WAF or limit is absent.

## License

MIT
