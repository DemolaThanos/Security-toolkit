# stride-model

Turns a small system model into a STRIDE review: spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege.

It raises a threat where the model is missing a control. A missing row is not an approval of the design. There are no attack steps and no payloads.

## Install

```bash
pip install .
```

Python 3.11 or newer.

## Usage

```bash
stride-model render examples/checkout.yaml
stride-model render model.yaml --format json --fail-on high
```

Exit codes: `0` the model rendered (and, with `--fail-on`, nothing reached the threshold), `1` a threat is at or above `--fail-on`, `2` the model is invalid. Without `--fail-on` the command is a generator and exits `0`. A model larger than 1 MB is rejected.

## Model

```yaml
name: checkout
description: Card checkout API and its order store.
trust_zones:
  - id: internet
    description: Customer network
    external: true
  - id: app
    description: Application tier
components:
  - id: api
    type: process          # external, process, or data-store
    zone: app
    description: Checkout API
    logs_actions: true     # optional
    rate_limited: true     # optional, used for internet-facing processes
    encrypted_at_rest: true
    data_classes: []
flows:
  - id: submit
    source: browser
    destination: api
    protocol: https        # https, tls, mtls, ssh, sftp, and wss are treated as protected
    authenticated: true    # required, so the model cannot leave it implicit
    data_classes: [credential, payment]
```

Zone ids `internet`, `public`, `external`, and `untrusted` are external when `external` is omitted. Set the boolean to override that.

Sensitive classes are `credential`, `payment`, `pii`, `phi`, `secret`, `session`, and `token`. Other class names are kept and treated as not sensitive.

`examples/checkout.yaml` declares authentication, TLS, logging, encryption, and a rate limit. The only residual threat is denial of service at low severity, because the limit is declared and still has to be confirmed.

## License

MIT
