# Phone-approved DriftGuard baselines

`production_monitor.py` can require that the approved baseline was approved on an
enrolled Frequency Guardian phone. Without that approval it reports `error` and
does not run the verifier.

## What this protects

The baseline's Ed25519 signature alone is only as trustworthy as the place its
signing key lives. With phone approval, accepting a baseline also needs:

1. an action request signed by the **independent Guardian authority**, which runs
   on a separate machine, never on the monitored host; and
2. an **approve** receipt signed by the enrolled phone's non-exportable Android
   Keystore key over exactly that request.

The request text names the baseline's SHA-256 and the monitored endpoint, so an
approval covers one exact baseline file. A replaced baseline needs a new tap.

What it does not protect: someone with full control of the monitored host can
still edit the monitor, its config or its pins, or stop it. Phone approval makes
the *baseline* independently approved; the monitor process itself still runs on,
and trusts, that host. The monitor also does not consult the authority's
revocation ledger. After revoking a phone, remove or replace the monitor's
`guardian_approval` pins.

## Approving a baseline

On the authority machine, with the new `approved-baseline.json`:

```sh
python3 scripts/guardian_baseline_approval.py action --baseline approved-baseline.json
python3 scripts/guardian_offline.py AUTHORITY request --device DEVICE --action "PRINTED TEXT" > request.fg
```

Import `request.fg` on the phone within 120 seconds. Check that the baseline SHA-256
on screen matches, tap **Approve** and export the receipt. Then:

```sh
python3 scripts/guardian_offline.py AUTHORITY verify --receipt receipt.json
python3 scripts/guardian_baseline_approval.py bundle --request request.fg \
  --receipt receipt.json --out baseline-approval.json
```

Copy `approved-baseline.json` and `baseline-approval.json` to the monitored host.

## Monitor configuration

Add `guardian_approval` to `approved-monitor.json` and label the trust model:

```json
{
  "trust_model": "GUARDIAN_PHONE_APPROVED",
  "guardian_approval": {
    "bundle": "/home/USER/.config/mcp-driftguard/baseline-approval.json",
    "authority_spki_b64": "AUTHORITY PUBLIC KEY (guardian_offline.py AUTHORITY public-key)",
    "device_spki_b64": "ENROLLED PHONE KEY (authority ledger, devices[DEVICE].spki)",
    "apk_signer_sha256": "APK SIGNER SHA-256 from the authority policy",
    "enrollment": "ENROLLMENT ID from the authority ledger"
  }
}
```

Get these values from the authority and confirm the authority fingerprint through
a separate channel, as for phone pinning. Deploy
`guardian_baseline_approval.py` next to `production_monitor.py`. The monitor
needs the Python `cryptography` package only when `guardian_approval` is set.

Check a configuration without waiting for the timer:

```sh
python3 guardian_baseline_approval.py verify --config approved-monitor.json
```
