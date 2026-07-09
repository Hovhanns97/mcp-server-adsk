# ACC MCP Server (for Claude web)

A remote Model Context Protocol server that lets Claude on **claude.ai** browse
your Autodesk Construction Cloud (ACC) hubs/projects/files and hand you a
link that opens the actual model in a hosted Autodesk Viewer page.

Why this shape: Claude web only connects to **remote, publicly-reachable
MCP servers** (Streamable HTTP). It cannot run a local stdio server on your
Mac, and it cannot render the real Autodesk Viewer (WebGL + Autodesk's own
JS/CSS) inline in the chat — so the `get_viewer_link` tool gives you a URL
that opens a small hosted viewer page in your browser instead.

---

## 1. Create an APS app (3-legged)

1. Go to <https://aps.autodesk.com/myapps> and create a new app.
2. Choose app type **"Traditional Web App"** (this is the 3-legged OAuth
   type — you need this, not "Server-to-Server", because the MCP server
   needs to act *as you* to see your ACC projects).
3. Set the **Callback URL** to:
   `https://YOUR-DOMAIN/aps/callback`
   (use the same domain you'll deploy to in step 3 — you can update this
   later once you know it).
4. Note the **Client ID** and **Client Secret**.

## 2. Provision the app in ACC

Your APS app needs to be added as a custom integration in your ACC
account before it can see any projects:

1. In the ACC/BIM 360 admin panel, go to **Account Admin > Custom
   Integrations** and add your APS app (by Client ID).
2. Add it to the specific projects you want visible (or give it account-wide
   access, depending on your admin settings).

## 3. Deploy the server

This is a plain Node.js/Express app — deploy it anywhere that gives you a
public HTTPS URL. Render.com's free tier is the easiest for testing:

```bash
cd acc-mcp-server
npm install
```

**Render.com (easiest):**
1. Push this folder to a GitHub repo.
2. On Render: New > Web Service > connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Add environment variables (see `.env.example`) in Render's dashboard.
5. Once deployed, Render gives you a URL like `https://acc-mcp.onrender.com`
   — set that as `PUBLIC_BASE_URL`, redeploy, and also update the APS app's
   callback URL (step 1.3) to `https://acc-mcp.onrender.com/aps/callback`.

**Any other host (Fly.io, Railway, a VPS, AWS):** same idea — just make sure
the process is reachable over HTTPS at the domain you put in
`PUBLIC_BASE_URL`.

Local test only (not reachable by Claude, but useful for sanity-checking):
```bash
npm start
```

## 4. Add it as a custom connector in Claude

1. In claude.ai: **Settings > Connectors** (or the "+" button in a chat >
   "Connectors").
2. Click **Add custom connector**.
3. Paste your server's MCP URL: `https://YOUR-DOMAIN/mcp`
4. Click **Add**. Claude will discover the OAuth endpoints automatically
   (via `/.well-known/oauth-authorization-server`) and walk you through
   logging into Autodesk — you'll see Autodesk's real login/consent screen.
5. Enable the connector for your conversation (per-conversation toggle via
   the "+" button > Connectors).

## 5. Using it

Once connected, you can ask things like:

- "List my ACC hubs"
- "Show me the projects in [hub name]"
- "List the files in the Project Files folder of [project name]"
- "Give me a link to open [model name] in the viewer"

The last one returns a URL — open it in your browser to see the real
Autodesk Viewer with your model loaded.

---

## Notes on what's simplified here

- **Token storage is in-memory.** Restarting the server logs everyone out
  and drops in-flight OAuth handshakes. For anything beyond testing, swap
  the `Map()`s in `server.js` (`sessions`, `authCodes`, `mcpTokens`) for a
  Postgres table — since you're already running Postgres locally, something
  like:

  ```sql
  create table mcp_sessions (
    session_id uuid primary key,
    aps_access_token text,
    aps_refresh_token text,
    aps_expires_at timestamptz
  );
  ```

  is a drop-in replacement for the `sessions` Map.

- **Single ACC integration only.** This doesn't distinguish between
  multiple Autodesk accounts/users beyond one OAuth session per browser
  login — fine for personal use, would need per-user scoping for a team.

- **Tools are read/browse-only** (`list_hubs`, `list_projects`,
  `list_top_folders`, `list_folder_contents`, `get_viewer_link`). Adding
  ACC Issues, markups, or write actions means adding more tools that call
  the corresponding APS endpoints the same way — the pattern in
  `server.js` (`mcp.registerTool(...)`) is copy-pasteable.

- **Viewer page uses your 3-legged session token.** ACC/BIM 360-hosted
  derivatives require the viewing user's own account access — a generic
  app-level 2-legged token can't read their manifests — so the viewer link
  is tied to your login and expires with the short-lived signed link (15
  min), not a separate long-lived credential.
