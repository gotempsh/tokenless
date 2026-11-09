// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The set-up prompt the home page's "Copy prompt" button copies, for a
// coding agent to install tokenless and add services with the user.

export const agentPrompt = `Set up tokenless on this machine, so you can call APIs for me without ever seeing my API keys.

tokenless is a credential broker for AI agents: https://github.com/gotempsh/tokenless
Its documentation: https://github.com/gotempsh/tokenless/tree/main/site/docs/content

1. Install it: curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
2. Install its agent skill and read it: npx skills add gotempsh/tokenless
3. If no tokenless control plane is running, ask me to start one in a terminal of my own with \`tokenless serve --data-dir ./data\` and to save the admin password it prints. Then ask me to run \`tokenless login\`.
4. Ask me which services you need, such as GitHub or OpenAI. For each one, give me the command to run in my own terminal, for example \`tokenless service add github --vault work --bundle my-agent\`; it asks me for the token. Never ask me to paste a token into this chat, and never read one from a file or an environment variable.
5. Enrol this machine as a proxy with \`tokenless proxy add --name laptop\`, then ask me to keep \`tokenless node run\` running in a terminal of my own.
6. Check that it works with \`tokenless run --vault work --bundle my-agent -- tokenless session info\`. From then on, run anything that calls those services as \`tokenless run --vault work --bundle my-agent -- <command>\`.`;
