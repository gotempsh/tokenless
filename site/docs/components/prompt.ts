// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The set-up prompt the home page's "Copy prompt" button copies, for a
// coding agent to install tokenless and add services with the user.

export const agentPrompt = `Set up tokenless on this machine, so you can call APIs for me without ever seeing my API keys.

tokenless is a credential broker for AI agents: https://github.com/gotempsh/tokenless
Its documentation: https://github.com/gotempsh/tokenless/tree/main/site/docs/content

1. Install it: curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
2. Install its agent skill and read it: npx skills add gotempsh/tokenless
3. Run \`tokenless status --json\`. It checks what is set up and its \`next\` is the command to run; run it again after each step until \`ready\` is true.
4. If no tokenless control plane is running, ask me to start one in a terminal of my own with \`tokenless serve --data-dir ~/.tokenless\` and to save the admin password it prints. Its data directory holds the root key, so keep it out of any repository. Then ask me to run \`tokenless login\` there too. It also runs the proxy your commands go through on this machine; if \`tokenless status\` still reports no proxy (version 0.3 and earlier don't run one), follow its \`next\`.
5. Ask me which services you need, such as GitHub or OpenAI, and find each one's template with \`tokenless service templates <name or variable> --json\`. Then run \`tokenless service add <template> --vault personal --bundle my-agent --secret-file --open\` in the background and tell me the file it opens: I paste the key there and save, and it deletes the file once the key is stored. Or use \`--web --open\` instead of \`--secret-file --open\` for me to enter it in the console. Never ask me to paste a token into this chat, and never read that file, another file or an environment variable for one.
6. Check that it works with \`tokenless run --vault personal --bundle my-agent -- tokenless session info\`. From then on, run anything that calls those services as \`tokenless run --vault personal --bundle my-agent -- <command>\`.`;
