# subtake

Authorised check for dangling CNAMEs. You give it hostnames. It follows each CNAME chain and compares the target with a small fingerprint file: provider patterns, NXDOMAIN behaviour, and HTTP response text. Every name comes back as likely-vulnerable, edge-case, or not-vulnerable, with the chain and the response that led there.

Use it only on hostnames you own or have written permission to test. Unauthorised scanning is illegal in a lot of places. The command refuses to run without `--i-am-authorized` or `SUBTAKE_AUTHORIZED=1`. That flag is an acknowledgement, not a permission slip.

subtake does not claim a name, does not try credentials, and does not guess labels. It does not follow redirects. It only sends HTTP when a name in the CNAME chain matches a fingerprinted service and every address in the answer is public. HTTPS is verified against that provider name, the name on the certificate. The `Host` header is the name you listed, which is what the provider uses to route the site. If TLS fails, it tries HTTP once. Verification is not disabled. It will not connect to a private, link-local, or other non-public address, including when only one address in the set is non-public. A likely-vulnerable result means the target name looks unclaimed on a service where that name can be registered. It is not proof. Confirm it, then remove the CNAME or point it at a resource you control. An edge-case is a dangling record you still check by hand: the provider is not considered claimable, or the signature is ambiguous.

## Install

```bash
pip install .
```

Python 3.11 or newer. The only runtime dependency is dnspython.

## Usage

```bash
subtake check hosts.txt --i-am-authorized
subtake check hosts.txt --i-am-authorized --format json --fail-on edge
subtake check - --i-am-authorized --format sarif --output subtake.sarif < hosts.txt
```

`hosts.txt` is one hostname per line. Blank lines and `#` comments are ignored, and a repeated name is checked once. `-` reads stdin. `examples/hosts.txt` is a sample of documentation names.

Exit codes: `0` nothing at or above `--fail-on` (default `likely`), `1` findings, `2` bad input, a refused run, or a check that threw. `--fail-on edge` also fails on edge cases, so a clean run can gate CI. DNS and HTTP failures stay edge-case. An unexpected error on one host still writes the report for the hosts that finished, then exits `2`. DNS and HTTP share one rate limit (default 5 per second) across the worker pool (default 8). `--timeout` (default 5 seconds) applies to each DNS query and each connection. Chains longer than 8 are not followed. `SUBTAKE_LOG_FORMAT=json` writes one JSON object per log line. The User-Agent is `subtake/<version>`.

```yaml
- run: pip install ./subtake
- run: subtake check hosts.txt --i-am-authorized --format sarif --output subtake.sarif
```

## Output

`table` is the default. `json` includes every host. `sarif` includes likely-vulnerable and edge-case results and omits not-vulnerable ones. SARIF results include a stable `partialFingerprints.primaryLocationLineHash`.

```
verdict            host                 service    evidence
likely-vulnerable  assets.example.com   Amazon S3  assets.example.com -> bucket.s3.amazonaws.com; HTTP 404 matched Amazon S3
not-vulnerable     www.example.com      -          no CNAME

1 likely-vulnerable, 0 edge-case, 1 not-vulnerable
```

## Fingerprints

`src/subtake/data/fingerprints.json` is the bundled set. Each entry names the service, lists CNAME patterns (`*` is a glob, and the pattern has to end in at least two literal labels), sets an NXDOMAIN verdict, and lists HTTP body snippets with an optional status code. `on_miss` is the verdict when the status is outside 200-399 and no snippet matched. A 200-399 response with no snippet is not-vulnerable. `--fingerprints` replaces the bundled file.

The service is the first CNAME in the chain that matches a pattern. That name is the one checked on the TLS certificate. A later hop the provider uses internally does not hide the match, and it does not inherit an NXDOMAIN verdict: NXDOMAIN is `likely-vulnerable` only when the name that failed to resolve is itself a claimable target. Every address in the answer is checked. One non-public address refuses the lot. More than 64 addresses is an edge case and is not probed.

`likely-vulnerable` is only used where the target name is considered registrable: Amazon S3 (the missing-bucket text), Elastic Beanstalk, Azure API Management, App Service, Blob Storage, CDN, Cloud Services, Storage static websites, and Traffic Manager, plus Bitbucket Pages, Ghost, Help Scout, Surge, and Railway. A disabled Traffic Manager profile also returns NXDOMAIN, so confirm it. GitHub Pages, Heroku, Shopify, Vercel, Netlify, Tumblr, Pantheon, CloudFront, Elastic Load Balancing, Fastly, Firebase, Fly.io, Google Cloud Storage, Zendesk, Azure Front Door, and Azure Static Web Apps stay `edge-case` when their error text or NXDOMAIN shows up. The default gate does not fail on those.

The error strings, and which of them are claimable, follow the public notes in [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) (MIT, EdOverflow and contributors). Those notes are a guide, not a proof the name can be registered. The bundled patterns cover GitHub Pages, Amazon S3, CloudFront, Elastic Load Balancing, Elastic Beanstalk, Google Cloud Storage, Heroku, several Azure endpoints, Fastly, Shopify, Surge, Bitbucket Pages, Ghost, Fly.io, Vercel, Pantheon, Firebase Hosting, Netlify, Zendesk, Help Scout, Tumblr, and Railway.

## License

MIT
