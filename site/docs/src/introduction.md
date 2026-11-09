<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

<div class="copy-prompt-bar"><button type="button" class="copy-prompt" data-copy-target="agent-prompt" hidden><svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M4 16V5a2 2 0 0 1 2-2h11"/></svg><span>Copy prompt</span></button></div>

# tokenless

tokenless gives AI agents access to APIs without giving them the keys.

```sh
curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
npx skills add gotempsh/tokenless     # the agent skill
```

Or let your coding agent set it up: **Copy prompt** and paste it into
Claude Code, Codex or any other agent. It installs tokenless and walks
you through adding your services, and you type every token into your
own terminal, never into the chat.

<details class="agent-prompt">
<summary>The prompt</summary>

<pre id="agent-prompt">Set up tokenless on this machine, so you can call APIs for me without ever seeing my API keys.

tokenless is a credential broker for AI agents: https://github.com/gotempsh/tokenless
Its documentation: https://github.com/gotempsh/tokenless/tree/main/site/docs/src

1. Install it: curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
2. Install its agent skill and read it: npx skills add gotempsh/tokenless
3. If no tokenless control plane is running, ask me to start one in a terminal of my own with `tokenless serve --data-dir ./data` and to save the admin password it prints. Then ask me to run `tokenless login`.
4. Ask me which services you need, such as GitHub or OpenAI. For each one, give me the command to run in my own terminal, for example `tokenless service add github --vault work --bundle my-agent`; it asks me for the token. Never ask me to paste a token into this chat, and never read one from a file or an environment variable.
5. Enrol this machine as a proxy with `tokenless proxy add --name laptop`, then ask me to keep `tokenless node run` running in a terminal of my own.
6. Check that it works with `tokenless run --vault work --bundle my-agent -- tokenless session info`. From then on, run anything that calls those services as `tokenless run --vault work --bundle my-agent -- &lt;command&gt;`.</pre>

</details>

You store a credential once, for example a GitHub token. An agent then
sends its HTTPS traffic through a tokenless proxy with a short-lived
session. For the hosts its session allows, the proxy adds the real
credential to the request on the way out. The agent can call the API,
but it never holds the key, so it can't leak it, paste it into a log or
keep using it after the job.

```text
agent ──HTTPS_PROXY──▶ proxy ──adds Authorization──▶ api.github.com
                         ▲
                         │ signed policy, sealed credentials
                    control plane (console, API, vaults)
```

## What you get

- **Secrets are write-only.** They are encrypted at rest with AES-256-GCM.
  Nobody can read one back, admins included. They only ever travel,
  sealed, to enrolled proxies.
- **Sessions are scoped and short-lived.** A session is bound to one vault,
  a set of rules, a lifetime (15 minutes by default) and optionally a
  request limit. Revoking one reaches the proxy within seconds.
- **Agents start with one command.** `tokenless run --bundle code-review -- claude`
  starts the agent behind a local proxy address with the right CA trusted
  and no token in its environment.
- **The proxy fails closed.** It runs from a signed, leased policy
  snapshot. When the lease lapses it refuses traffic, and it never injects
  a credential it can't audit.
- **No pivoting into your network.** By default the proxy won't connect to
  loopback, private, link-local or cloud metadata addresses.
- **Everything is audited**: every change, every injected request and
  every refusal.

## How it fits together

- **`tokenless serve`** runs the control plane: the web console, the
  management API, and the node API that proxies connect to. It stores
  everything in SQLite.
- **`tokenless node run`** runs a proxy, normally on the machine your
  agents run on.
- **`tokenless run`**, **`tokenless mcp`** and the other client commands
  start agents and MCP clients behind a proxy.

All three are the same binary.

Start with [Install](install.md) and the [Quickstart](quickstart.md).
