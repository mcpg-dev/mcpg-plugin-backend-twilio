# Twilio SMS + Voice Binding (`dev.mcpg.backend.twilio`)

One cdylib carrying **three entities** that together let an AI agent fully
orchestrate Twilio SMS + Voice through MCP:

- a **`backend` binding** whose operations proxy the Twilio REST API
  (send/list/get/redact/delete SMS, make/list/get/modify calls, recordings,
  local TwiML authoring, call-response staging, and an opt-in
  `configure_number_webhooks`). One binding == one `operation` (the
  `dynamodb` / `soap` op-discriminated envelope model). A binding may serve the
  **tool** surface (default) or the **resource** surface (`twilio://message/{sid}`
  reads + `resources/list`).
- an **`http_route` entity** mounted at
  `/plugins/dev.mcpg.backend.twilio/hooks/*` that receives Twilio's inbound
  SMS / voice / gather / status webhooks, validates `X-Twilio-Signature`
  (HMAC-SHA1, constant-time) **before any side effect**, records the event into
  a shared in-process ring, runs three inbound-control levels, and returns
  TwiML.
- a **`watch_strategy` entity** (kind `twilio_inbound`) that pushes
  `notifications/resources/updated` to subscribed MCP clients **natively** when
  an inbound webhook lands — no `notify_webhook_url` HTTP round-trip. The
  webhook is the source: it publishes an in-process notice that this entity's
  dispatcher fans out to registered watchers, filtered by an optional `kinds`
  watch-spec.

Transport is pure-Rust `reqwest` + `rustls` — no native-tls / OpenSSL.

## Auth

- `account_sid` is always required (embedded in the REST URL and is the
  webhook-signing identity).
- REST credentials: an **API Key** (`api_key_sid` + `api_key_secret`,
  recommended) **or** the Account **Auth Token** as the HTTP Basic password.
- Webhook signature validation is **always** keyed by the Account **Auth
  Token** — API Key secrets do not sign webhooks. So the `http_route` entity is
  configured with `auth_token`.
- All secrets resolve from `${cred://…}` at config load. A bare `cred://` in a
  request argument is rejected.

## Backend operations

| `operation` | Twilio call | Key args |
|---|---|---|
| `send_sms` | `POST Messages.json` | `to`, `body`, `from`\|`messaging_service_sid`, `media_url[]`, `status_callback` |
| `list_messages` | `GET Messages.json` | `to?`, `from?`, `date_sent?` (follows `next_page_uri`) |
| `get_message` | `GET Messages/{sid}.json` | `sid` |
| `redact_message` | `POST Messages/{sid}.json` (Body="") | `sid` |
| `delete_message` | `DELETE Messages/{sid}.json` | `sid` |
| `make_call` | `POST Calls.json` | `to`, `from`, `twiml_verbs`\|`twiml`\|`url`, `status_callback`, `record`, `machine_detection` |
| `list_calls` | `GET Calls.json` | `to?`, `from?`, `status?` |
| `get_call` | `GET Calls/{sid}.json` | `sid` |
| `modify_call` | `POST Calls/{sid}.json` | `sid`, `action`=hangup\|redirect, `url?`\|`twiml_verbs?` |
| `get_recording` | `GET Recordings/{sid}.json` | `sid` |
| `lookup` | `GET lookups.twilio.com/v2/PhoneNumbers/{phone}` | `phone`, `fields[]?` (`line_type_intelligence`, `caller_name`) |
| `verify_start` | `POST verify.twilio.com/v2/Services/{VA}/Verifications` | `to`, `channel?`=sms\|call\|email |
| `verify_check` | `POST verify.twilio.com/v2/Services/{VA}/VerificationCheck` | `to`, `code` |
| `build_twiml` | *(local)* | `twiml_verbs[]` → returns the TwiML string |
| `stage_call_response` | *(local → state)* | `call_sid?`\|`to?`, `twiml_verbs[]`, `ttl_secs?` |
| `configure_number_webhooks` | `POST IncomingPhoneNumbers/{sid}.json` | `sid`, `sms_url?`, `voice_url?`, `status_callback?` (opt-in) |

### Phone validation + OTP

`lookup`, `verify_start`, and `verify_check` call distinct Twilio API
subdomains (`lookups.twilio.com`, `verify.twilio.com`) using the same HTTP
Basic auth as the account REST host. The hosts are operator-fixed Twilio
endpoints (overridable only via `lookups_base` / `verify_base` for testing).

- **`lookup`** — validate a phone number and (optionally) pull carrier /
  line-type and caller-name data. The `phone` argument is percent-encoded into
  the path (so a `+` in an E.164 number can't break out of its segment), and
  `fields` is joined into Twilio's `Fields` query param. Example:

  ```json
  { "phone": "+15551234567", "fields": ["line_type_intelligence", "caller_name"] }
  ```

  → `{ "valid": true, "line_type_intelligence": { "type": "mobile", … }, "caller_name": { … } }`.

- **OTP flow** — `verify_start` then `verify_check`, both against a Verify v2
  Service configured per-binding as `verify_service_sid` (`VA…`):

  ```json
  // verify_start — sends the code over the chosen channel
  { "to": "+15551234567", "channel": "sms" }      // → { "status": "pending", … }
  // verify_check — validates the code the user entered
  { "to": "+15551234567", "code": "123456" }      // → { "status": "approved", … }
  ```

  `verify_service_sid` is a public service identifier (not a secret), but
  follows the config convention — a bare `cred://` in it is rejected.

`twiml_verbs` is an ordered array of structured verbs (`say`, `play`, `gather`
with nesting, `record`, `dial`, `reject`, `hangup`, `pause`, `redirect`,
`message`) rendered to escaped XML. An unknown verb is rejected.

Twilio's logical failures (`{code, message, more_info, status}` — e.g. 21211
invalid `To`, 21610 unsubscribed) are mapped to a tool-level error envelope
(`isError: true`). Real failures (connection / 5xx / timeout) surface as
`BackendError`. Retries apply only to connection / 5xx / 429 (honouring
`Retry-After`); `send_sms` is therefore **at-least-once** (Twilio has no
idempotency key).

## Webhook routes + inbound control

- `POST /hooks/sms` — inbound SMS → record → optional handler tool → static
  templated auto-reply → empty `<Response/>`.
- `POST /hooks/voice` — inbound call → record → **(1)** a staged script for the
  `CallSid`/`To` (via `stage_call_response`), else **(2)** the `handler_tool`
  (`invoke_tool` → its `{twiml_verbs}`/`{text}` result), else **(3)** the
  templated `default_twiml_verbs`, else a safe `<Reject/>`.
- `POST /hooks/gather/:id` — `<Gather>` digit/speech callback → handler tool
  with the captured input → next TwiML turn (IVR loop).
- `POST /hooks/status` — status callbacks → update state → `204`.

The signature is validated over the reconstructed public URL
(`public_base_url` + path + raw query) + sorted POST params for form bodies, or
the URL alone (carrying `bodySHA256`) for JSON bodies. A mismatch returns `403`
with no side effects. `validate_signature: false` is a local-dev escape hatch
(default `true`, warns loudly).

## Native push (`watch_strategy`, kind `twilio_inbound`)

Inbound webhooks are the source — there is nothing external to poll. When the
`http_route` handler records an inbound event it also publishes an in-process
`InboundNotice` (a non-blocking send). The `twilio_inbound` watch entity runs
one dispatcher task on its **own** runtime that drains those notices and calls
the host's `emit_event` for every matching watcher, making the gateway emit
`notifications/resources/updated` for the watched collection URI. Because the
dispatcher runs off the webhook's runtime, `emit_event` is always invoked
outside the webhook's `block_on` — no nested `block_on`, no deadlock.

Per-watch spec (the resource's `strategy` block):

```yaml
strategy:
  kind: twilio_inbound
  # optional: which inbound kinds fire this watch (default: all three)
  kinds: [sms, voice, status]
```

Operator story: declare a resource watch with `strategy.kind: twilio_inbound`
on a collection URI (e.g. `twilio://messages`); a client `resources/subscribe`s
to it; an inbound SMS then drives `resources/updated`, and the client re-reads
the fresh message from Twilio's REST API. The `WatchEvent` payload carries no
`user_id` / `session_id` (Twilio inbound is not tied to an MCP session).

`notify_webhook_url` remains the **cross-replica** push alternative: the native
watch is in-process (single-replica), matching the state caveat below.

## State (single-gateway affinity)

The three entities share an in-process `TwilioState`: a bounded ring (~256) of
recent inbound events, a TTL'd staged-script map (`CallSid`/`To` → verbs), a
last-status map, and the inbound-notice channel + watch registry the
`twilio_inbound` entity drains. It is **not** durable or cluster-shared — an
inbound webhook lands on whichever replica Twilio reached, so live call
scripting **and the native watch push** are tied to that replica. Twilio's REST
API remains the source of truth for message/call history (the `list_*`/`get_*`
ops read it directly).

## Operator quickstart

1. Configure the backend bindings (`kind: twilio`, one per `operation`) with
   `account_sid` + REST credentials. Configure the webhook entity with
   `account_sid`, `auth_token`, `public_base_url`, and inbound control.
2. The webhook base is `{public_base_url}/plugins/dev.mcpg.backend.twilio/hooks`.
3. In Twilio, set the number's Voice URL → `.../hooks/voice`, SMS URL →
   `.../hooks/sms`, status callbacks → `.../hooks/status` (or call
   `configure_number_webhooks`).

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
