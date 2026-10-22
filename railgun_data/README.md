# railgun_data

Local Railgun note tree for this node. Bind-mounted to `/app/railgun_data` in `continuum-mcp`.

An MCP image update keeps this directory. It is not copied to other nodes in the KeyGen.

- `engine/` — LevelDB: chain note trees and scan positions
- `artifacts/` — proof files
- `keygens/<keyGenId>/wallet.json` — that KeyGen’s wallet id

Do not put viewing keys or spending shares here.
