# Sundew README demo. Regenerate with `vhs docs/demo.tape` from the repo root
# (needs sundew, curl and jq on PATH; writes docs/demo.gif).

Output docs/demo.gif

Require sundew
Require curl
Require jq

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 600
Set Padding 18
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 28ms
Set CursorBlink false

# Start a fintech honeypot in a scratch directory before recording
Hide
Type `export PS1='$ ' && cd "$(mktemp -d)" && sundew generate -i fintech -s 7 -o persona.yaml >/dev/null`
Enter
Type `printf 'persona: persona.yaml\nllm:\n  provider: none\nstorage:\n  database: data/sundew.db\n  log_file: data/events.jsonl\nlogging:\n  level: warning\n' > sundew.yaml`
Enter
Type `(sundew -c sundew.yaml serve >/dev/null 2>&1 &) && until curl -s localhost:8080/health >/dev/null; do sleep 0.2; done; clear`
Enter
Sleep 3s
Show

Type "# Every deployment gets its own identity"
Sleep 400ms
Enter
Type "sundew generate --industry fintech --seed 7"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Type "sundew generate --industry healthcare --seed 42"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Type "# An AI agent finds the fintech deployment's plugin manifest..."
Sleep 400ms
Enter
Type `curl -s localhost:8080/.well-known/ai-plugin.json | jq '{name_for_model, description_for_model}'`
Sleep 400ms
Enter
Sleep 3s
Type "# ...and its MCP server, with tools that match the persona"
Sleep 400ms
Enter
Type `curl -sd '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' localhost:8080/mcp | jq -r '.result.tools[].name'`
Sleep 400ms
Enter
Sleep 5s
