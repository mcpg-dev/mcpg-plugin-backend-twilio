# Twilio plugin — configuration examples

[`config.yaml`](./config.yaml) is a complete, annotated gateway config that wires
all three entities of `dev.mcpg.backend.twilio`. This README explains the config
nuances that aren't obvious from the schema.

Validate it offline (no Twilio account needed):

```bash
cargo run -p mcpg --bin mcpg-config -- check \
  --config libs/plugins/backend/twilio/examples/config.yaml
```

## One artifact, three entities

The cdylib is loaded once under the top-level `plugins:` list. It carries three
entities, and **each gets its config from a different place**:

| Entity | What it does | Config source |
|---|---|---|
| `backend` | SMS/Voice **tools** + a resource surface | the per-binding `backend:` block on each tool/resource |
| `http_route` | **inbound webhooks** (`/hooks/sms\|voice\|status\|gather/:id`) → TwiML | the `config:` block on the `plugins:` entry |
| `watch_strategy` | **push** `notifications/resources/updated` on inbound events | the per-watch `strategy:` spec |

So the webhook's account/auth/public-URL/inbound behaviour lives in
`plugins[].config`, while each tool's auth + operation lives in its own
`backend:` block.

## Auth model — the subtlety

- **`account_sid`** is always required (it's both the REST URL path segment and
  the identity Twilio signs webhooks with).
- **REST tools** authenticate with either an **API Key** (`api_key_sid` +
  `api_key_secret`, recommended — scoped + revocable) or the Account **Auth
  Token** as the basic-auth password.
- **Webhook signatures are ALWAYS keyed by the Account Auth Token**, never an API
  Key secret. So even if your tools use an API key, the `http_route` entity's
  `config:` must include `auth_token`. (This trips people up — an API key alone
  cannot validate an inbound webhook.)
- All secrets use `cred://dev.mcpg.backend.twilio/<target>` so they resolve from
  the gateway credential cache and are never inlined or logged. `${env.VAR}` is
  fine for non-secret IDs (account SID, API key SID).

## The webhook URL (the "special URL")

Routes mount under the plugin's namespaced path:

```
{public_base_url}/plugins/dev.mcpg.backend.twilio/hooks/<route>
```

In the Twilio console (or via the `configure_number_webhooks` tool) set the
number's:
- **Voice URL** → `.../hooks/voice`
- **Messaging URL** → `.../hooks/sms`
- **Status callback** → `.../hooks/status`

`public_base_url` must be set explicitly: signature validation reconstructs the
*exact* URL Twilio called, and behind a proxy/LB the gateway can't infer the
external scheme/host. A wrong base silently fails every signature.

## Signature validation (fail-closed)

Every webhook is validated against `X-Twilio-Signature` **before any side
effect** — a bad or missing signature returns `403` with no TwiML and no state
change (constant-time compare; form + JSON-`bodySHA256` variants). It defaults to
on; set `validate_signature: false` only for local `curl` testing.

## Controlling inbound calls — three complementary levels

1. **Static / templated** — `inbound_voice.default_twiml_verbs` (and
   `inbound_sms.auto_reply`). `${From}`/`${To}`/`${CallSid}` substitute from the
   inbound params. Zero agent involvement.
2. **Agent pre-staged** — the agent calls the `stage_call_response` tool to queue
   TwiML for a specific `CallSid` (or an expected `To`); the webhook serves it
   once. Lets the agent script a call ahead of time.
3. **Live handler tool** — set `inbound_voice.handler_tool` /
   `inbound_sms.handler_tool` to a tool name; the webhook `invoke_tool`s it per
   turn (passing the inbound params + any `<Gather>` speech/DTMF) and renders the
   returned `twiml_verbs`. This is the interactive IVR loop. It's bounded by
   `handler_timeout_ms` (kept well under Twilio's ~15 s webhook timeout) and falls
   back to the static flow on slow/error.

`twiml_verbs` is an ordered list of structured verbs (`say`, `play`, `gather`,
`record`, `dial`, `reject`, `hangup`, `pause`, `redirect`, `message`) — the
plugin renders valid TwiML, so the agent never writes XML.

## Receiving inbound events as MCP entities

- **Pull** — `list_messages` / the `twilio://messages` resource / the
  `twilio://message/{sid}` template all proxy Twilio (the durable store). An agent
  can poll or read them any time.
- **Push** — declare a `watch:` with `strategy: { type: plugin, kind: twilio_inbound }`
  on a collection resource (see `twilio.inbox` in the sample). When a matching
  inbound event lands at the webhook, the `watch_strategy` entity fires
  `notifications/resources/updated` for that resource URI to every client that
  `resources/subscribe`d to it; the client then `resources/read`s to fetch the new
  data (the notification carries only the URI). The optional `kinds: [sms|voice|status]`
  filters which inbound events fire the watch.
  - `notify_webhook_url` is an alternative *cross-replica* push path (POSTs the
    built-in `/webhooks/resource-updated/{token}`) for multi-gateway HA, where the
    webhook may land on a different replica than the subscriber.

## Caveats

- **No idempotency key** — Twilio has none, so `send_sms`/`make_call` are
  at-least-once; a retried call double-sends. The bindings are annotated
  `idempotent: false`.
- **`configure_number_webhooks` mutates your Twilio account** — it's opt-in and
  capability-gated; only enable it where you want the gateway to (re)program a
  number's webhook URLs.
- **In-process state is single-gateway** — staged call scripts + the live-event
  ring live in the replica that handled the call's webhooks. Message/call history
  is always reread from Twilio (the source of truth), so only live call-scripting
  is replica-affine. Use `notify_webhook_url` for cross-replica push.
- **Network egress** — the plugin needs outbound HTTPS to `api.twilio.com`
  (`network_outbound`, declared in the manifest).
