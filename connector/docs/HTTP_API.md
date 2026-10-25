# Connector read-only HTTP API (Milestone 3a)

Disabled by default. Enable on the daemon:

    connector/bin/connector --config connector/config/connector0.conf \
        --http-port 8080 [--http-host 127.0.0.1] [--http-origin <origin>]

- Binds 127.0.0.1 unless `--http-host` says otherwise (a warning is logged for non-loopback: there is no authentication).
- On loopback, requests whose `Host` header is not 127.0.0.1/localhost/[::1] get 403 (DNS-rebinding guard).
- CORS: only the single exact origin given by `--http-origin` is echoed back. Wildcards are rejected. A page opened from `file://` sends `Origin: null`, so use `--http-origin null` for it, or serve the HTML from a local web server and pass that origin.
- GET and OPTIONS only. Nothing here changes state. POST etc. return 405.
- All u64 values (amounts, fees, nonces, versions, sequence numbers, counts of records) are decimal **strings**. Timestamps are JSON integers (Unix seconds).
- Errors: `{"error":{"code":"...","message":"..."}}`.

| Endpoint | Query | Notes |
|---|---|---|
| `GET /api/status` | | connector id/pubkey/quorum; per chain: configured endpoint and `connected`; peers configured/connected; stored activity count; transfer counts by state |
| `GET /api/topology` | | nodes + links. Chain nodes are `source:"configured"` (the one endpoint this connector uses per chain). `live` is true only for an authenticated link. `not_exposed` lists what the backend cannot report |
| `GET /api/activity` | `chain=a\|b`, `type=same_chain\|cross_chain`, `status=pending\|verified\|finalized\|rejected\|unavailable`, `since=<seq>`, `limit=1..200` (default 50) | oldest first, `since` exclusive; response has `next_since`, `has_more`, `total_stored` |
| `GET /api/activity/{record_id}` | | 64 hex chars |
| `GET /api/transfers` | `state=<STATE>`, `source_chain=a\|b`, `offset`, `limit=1..200` | newest first; `total_matching`, `has_more` |
| `GET /api/transfers/{transfer_id}` | | 64 hex chars |
| `GET /api/rates` | | A_to_B and B_to_A: num, den, version, updated_at, updater_pubkey, `signature_valid`, `valid`; plus the floor-division rule |

Semantics that matter for the UI:
- `reporter_signature_valid` means the reporting connector's signature and the record_id derivation verify. It is **not** proof of source-chain finality.
- `source_round` / `source_vertex_hash` are `null` when the connector did not receive them.
- `dest_tx_hash` is `null` until a destination transaction exists. `approvals` is the connector quorum, not destination execution.
- `rates[].signature_valid=false` with `version` 0 means the value comes from the config file and has never been signed.

Not yet implemented: transfer submission, rate updates, logs.
