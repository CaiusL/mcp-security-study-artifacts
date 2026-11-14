// Scan hosted MCP servers with MCP-Shield:  node scan-urls.mjs <url> [more urls] [mcp-shield options]
// Always passes --path to a temporary config holding only the given URLs. Without
// --path, mcp-shield reads this PC's Claude/Cursor/VS Code configs and starts their
// local servers.
import {spawnSync} from 'node:child_process'
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'

const isUrl = arg => /^https?:\/\//i.test(arg)
const args = process.argv.slice(2)
const urls = args.filter(isUrl)
if (!urls.length) {
  console.error('usage: mcp-shield <url> [more urls] [--claude-api-key KEY] [--identify-as NAME]')
  process.exit(2)
}

const mcpServers = Object.fromEntries(urls.map((url, i) => [`${i + 1}-${new URL(url).host}`, {url}]))
const dir = mkdtempSync(join(tmpdir(), 'mcp-shield-'))
const config = join(dir, 'mcp.json')
writeFileSync(config, JSON.stringify({mcpServers}, null, 2))

const cli = join(dirname(fileURLToPath(import.meta.url)), 'node_modules', 'mcp-shield', 'dist', 'index.js')
// --path goes last so it wins over any --path passed in.
const result = spawnSync(process.execPath, [cli, ...args.filter(arg => !isUrl(arg)), '--path', config], {stdio: 'inherit'})
rmSync(dir, {recursive: true, force: true})
process.exit(result.status ?? 1)
