require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const {
  PORT = 3000,
  PUBLIC_BASE_URL,           // e.g. https://acc-mcp.yourdomain.com  (NO trailing slash)
  APS_CLIENT_ID,
  APS_CLIENT_SECRET,
  JWT_SECRET,
} = process.env;

if (!PUBLIC_BASE_URL || !APS_CLIENT_ID || !APS_CLIENT_SECRET || !JWT_SECRET) {
  console.error('Missing required env vars. See .env.example');
  process.exit(1);
}

const APS_AUTH_BASE = 'https://developer.api.autodesk.com/authentication/v2';
const APS_DATA_BASE = 'https://developer.api.autodesk.com';
const APS_CALLBACK_PATH = '/aps/callback';
const APS_REDIRECT_URI = `${PUBLIC_BASE_URL}${APS_CALLBACK_PATH}`;

// Scopes: data:read to browse ACC/BIM360 projects & files, viewables:read to
// mint viewer tokens, account:read for hub/project metadata.
const APS_SCOPES = 'data:read viewables:read account:read';

// ---------------------------------------------------------------------------
// Storage (in-memory demo). Swap these Maps for your Postgres instance in
// production — e.g. `oauth_sessions(session_id, aps_access_token,
// aps_refresh_token, aps_expires_at)`. Keeping it in-memory here so the
// whole thing runs with zero external dependencies while you get it working.
// ---------------------------------------------------------------------------
const pendingAuthorizations = new Map(); // state -> { redirect_uri, code_challenge, client_state, mcp_client_id }
const authCodes = new Map();             // our_auth_code -> { sessionId, redirect_uri, code_challenge }
const sessions = new Map();              // sessionId -> { apsAccessToken, apsRefreshToken, apsExpiresAt }
const mcpTokens = new Map();             // mcpAccessToken -> sessionId
const registeredClients = new Map();     // client_id -> { redirect_uris }

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest();
}

// ---------------------------------------------------------------------------
// APS token helpers
// ---------------------------------------------------------------------------
async function exchangeCodeForApsTokens(code) {
  const res = await axios.post(
    `${APS_AUTH_BASE}/token`,
    new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: APS_REDIRECT_URI,
    }),
    {
      auth: { username: APS_CLIENT_ID, password: APS_CLIENT_SECRET },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }
  );
  return res.data; // { access_token, refresh_token, expires_in, ... }
}

async function refreshApsToken(refreshToken) {
  const res = await axios.post(
    `${APS_AUTH_BASE}/token`,
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: APS_SCOPES,
    }),
    {
      auth: { username: APS_CLIENT_ID, password: APS_CLIENT_SECRET },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }
  );
  return res.data;
}

async function get2LeggedViewerToken() {
  // 2-legged token, viewables:read only — safe to hand to a browser-side viewer.
  const res = await axios.post(
    `${APS_AUTH_BASE}/token`,
    new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'viewables:read',
    }),
    {
      auth: { username: APS_CLIENT_ID, password: APS_CLIENT_SECRET },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }
  );
  return res.data.access_token;
}

async function getValidApsAccessToken(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) throw new Error('No APS session — user needs to (re)authorize.');
  if (Date.now() < session.apsExpiresAt - 30_000) return session.apsAccessToken;
  const refreshed = await refreshApsToken(session.apsRefreshToken);
  session.apsAccessToken = refreshed.access_token;
  session.apsRefreshToken = refreshed.refresh_token || session.apsRefreshToken;
  session.apsExpiresAt = Date.now() + refreshed.expires_in * 1000;
  sessions.set(sessionId, session);
  return session.apsAccessToken;
}

function apsHeaders(token) {
  return { Authorization: `Bearer ${token}` };
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.type('text/plain').send('ACC MCP server is running. Connect to it at /mcp.');
});

// --- MCP OAuth discovery -----------------------------------------------
// These let Claude auto-discover how to authorize against this server.
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  res.json({
    resource: `${PUBLIC_BASE_URL}/mcp`,
    authorization_servers: [PUBLIC_BASE_URL],
  });
});

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: PUBLIC_BASE_URL,
    authorization_endpoint: `${PUBLIC_BASE_URL}/authorize`,
    token_endpoint: `${PUBLIC_BASE_URL}/token`,
    registration_endpoint: `${PUBLIC_BASE_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
  });
});

// --- Dynamic client registration (Claude calls this automatically) -----
app.post('/register', (req, res) => {
  const client_id = crypto.randomUUID();
  const { redirect_uris = [] } = req.body || {};
  registeredClients.set(client_id, { redirect_uris });
  res.status(201).json({
    client_id,
    redirect_uris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  });
});

// --- Step 1: Claude sends the user's browser here -----------------------
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  if (!redirect_uri || !code_challenge) {
    return res.status(400).send('Missing redirect_uri or code_challenge');
  }
  const apsState = crypto.randomUUID();
  pendingAuthorizations.set(apsState, {
    client_id,
    redirect_uri,
    client_state: state,
    code_challenge,
    code_challenge_method: code_challenge_method || 'S256',
  });

  const apsAuthUrl = new URL(`${APS_AUTH_BASE}/authorize`);
  apsAuthUrl.searchParams.set('response_type', 'code');
  apsAuthUrl.searchParams.set('client_id', APS_CLIENT_ID);
  apsAuthUrl.searchParams.set('redirect_uri', APS_REDIRECT_URI);
  apsAuthUrl.searchParams.set('scope', APS_SCOPES);
  apsAuthUrl.searchParams.set('state', apsState);
  res.redirect(apsAuthUrl.toString());
});

// --- Step 2: Autodesk redirects back here after the user logs in --------
app.get(APS_CALLBACK_PATH, async (req, res) => {
  const { code, state } = req.query;
  const pending = pendingAuthorizations.get(state);
  if (!pending) return res.status(400).send('Unknown or expired authorization state.');
  pendingAuthorizations.delete(state);

  try {
    const apsTokens = await exchangeCodeForApsTokens(code);
    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, {
      apsAccessToken: apsTokens.access_token,
      apsRefreshToken: apsTokens.refresh_token,
      apsExpiresAt: Date.now() + apsTokens.expires_in * 1000,
    });

    const ourCode = crypto.randomUUID();
    authCodes.set(ourCode, {
      sessionId,
      redirect_uri: pending.redirect_uri,
      code_challenge: pending.code_challenge,
      code_challenge_method: pending.code_challenge_method,
      createdAt: Date.now(),
    });

    const backToClaude = new URL(pending.redirect_uri);
    backToClaude.searchParams.set('code', ourCode);
    if (pending.client_state) backToClaude.searchParams.set('state', pending.client_state);
    res.redirect(backToClaude.toString());
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send('Failed to exchange code with Autodesk.');
  }
});

// --- Step 3: Claude exchanges our auth code for an MCP access token -----
app.post('/token', express.urlencoded({ extended: true }), async (req, res) => {
  const { grant_type, code, code_verifier, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: 'invalid_grant' });
    authCodes.delete(code);

    if (entry.code_challenge) {
      const expected = base64url(sha256(code_verifier || ''));
      if (expected !== entry.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    const mcpAccessToken = jwt.sign({ sessionId: entry.sessionId }, JWT_SECRET, { expiresIn: '1h' });
    const mcpRefreshToken = jwt.sign({ sessionId: entry.sessionId, refresh: true }, JWT_SECRET, { expiresIn: '180d' });
    mcpTokens.set(mcpAccessToken, entry.sessionId);

    return res.json({
      access_token: mcpAccessToken,
      refresh_token: mcpRefreshToken,
      token_type: 'Bearer',
      expires_in: 3600,
    });
  }

  if (grant_type === 'refresh_token') {
    try {
      const payload = jwt.verify(refresh_token, JWT_SECRET);
      const mcpAccessToken = jwt.sign({ sessionId: payload.sessionId }, JWT_SECRET, { expiresIn: '1h' });
      mcpTokens.set(mcpAccessToken, payload.sessionId);
      return res.json({ access_token: mcpAccessToken, token_type: 'Bearer', expires_in: 3600 });
    } catch {
      return res.status(400).json({ error: 'invalid_grant' });
    }
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// --- Middleware: resolve the ACC session from the Bearer token ----------
function sendUnauthorized(res, error) {
  const resourceMetadataUrl = `${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource`;
  res.set('WWW-Authenticate', `Bearer resource_metadata="${resourceMetadataUrl}"`);
  res.status(401).json({ error });
}

function requireSession(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return sendUnauthorized(res, 'unauthorized');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.sessionId = payload.sessionId;
    next();
  } catch {
    sendUnauthorized(res, 'invalid_token');
  }
}

// ---------------------------------------------------------------------------
// MCP server + ACC tools
// ---------------------------------------------------------------------------
function buildMcpServer(sessionId) {
  const mcp = new McpServer({ name: 'acc-mcp-server', version: '1.0.0' });

  mcp.registerTool(
    'list_hubs',
    {
      title: 'List ACC hubs',
      description: "List the Autodesk Construction Cloud / BIM 360 hubs the user's account can access.",
      inputSchema: {},
    },
    async () => {
      const token = await getValidApsAccessToken(sessionId);
      const { data } = await axios.get(`${APS_DATA_BASE}/project/v1/hubs`, { headers: apsHeaders(token) });
      const hubs = data.data.map(h => ({ id: h.id, name: h.attributes.name, type: h.attributes.extension?.type }));
      return { content: [{ type: 'text', text: JSON.stringify(hubs, null, 2) }] };
    }
  );

  mcp.registerTool(
    'list_projects',
    {
      title: 'List ACC projects in a hub',
      description: 'List projects within a given hub. Call list_hubs first to get a hub_id.',
      inputSchema: { hub_id: z.string().describe('Hub ID from list_hubs, e.g. "b.xxxxx"') },
    },
    async ({ hub_id }) => {
      const token = await getValidApsAccessToken(sessionId);
      const { data } = await axios.get(`${APS_DATA_BASE}/project/v1/hubs/${hub_id}/projects`, { headers: apsHeaders(token) });
      const projects = data.data.map(p => ({ id: p.id, name: p.attributes.name }));
      return { content: [{ type: 'text', text: JSON.stringify(projects, null, 2) }] };
    }
  );

  mcp.registerTool(
    'list_top_folders',
    {
      title: 'List top-level folders in a project',
      description: 'List the top-level folders (e.g. "Project Files") for a project. Needs hub_id and project_id.',
      inputSchema: { hub_id: z.string(), project_id: z.string() },
    },
    async ({ hub_id, project_id }) => {
      const token = await getValidApsAccessToken(sessionId);
      const { data } = await axios.get(
        `${APS_DATA_BASE}/project/v1/hubs/${hub_id}/projects/${project_id}/topFolders`,
        { headers: apsHeaders(token) }
      );
      const folders = data.data.map(f => ({ id: f.id, name: f.attributes.displayName }));
      return { content: [{ type: 'text', text: JSON.stringify(folders, null, 2) }] };
    }
  );

  mcp.registerTool(
    'list_folder_contents',
    {
      title: 'List contents of a folder',
      description: 'List sub-folders and items (files/models) inside a folder. Needs project_id and folder_id.',
      inputSchema: { project_id: z.string(), folder_id: z.string() },
    },
    async ({ project_id, folder_id }) => {
      const token = await getValidApsAccessToken(sessionId);
      const { data } = await axios.get(
        `${APS_DATA_BASE}/data/v1/projects/${project_id}/folders/${folder_id}/contents`,
        { headers: apsHeaders(token) }
      );
      const items = data.data.map(i => ({ id: i.id, type: i.type, name: i.attributes.displayName }));
      return { content: [{ type: 'text', text: JSON.stringify(items, null, 2) }] };
    }
  );

  mcp.registerTool(
    'get_viewer_link',
    {
      title: 'Get a viewer link for a model',
      description:
        "Get a hosted-viewer URL for a specific model item so the user can open it in their browser. Needs project_id and item_id (from list_folder_contents, where type is 'items').",
      inputSchema: { project_id: z.string(), item_id: z.string() },
    },
    async ({ project_id, item_id }) => {
      const token = await getValidApsAccessToken(sessionId);
      const { data: item } = await axios.get(
        `${APS_DATA_BASE}/data/v1/projects/${project_id}/items/${item_id}`,
        { headers: apsHeaders(token) }
      );
      const versionId = item.data.relationships.tip.data.id;
      const { data: version } = await axios.get(
        `${APS_DATA_BASE}/data/v1/projects/${project_id}/versions/${encodeURIComponent(versionId)}`,
        { headers: apsHeaders(token) }
      );
      const derivativeUrn = version.data.relationships.derivatives.data.id;
      const urnBase64 = Buffer.from(derivativeUrn).toString('base64').replace(/=/g, '');

      const viewerToken = jwt.sign({ urn: urnBase64 }, JWT_SECRET, { expiresIn: '15m' });
      const viewerUrl = `${PUBLIC_BASE_URL}/viewer?session=${viewerToken}`;
      return {
        content: [
          {
            type: 'text',
            text: `Open this link in a browser to view the model:\n${viewerUrl}\n\n(Link expires in 15 minutes.)`,
          },
        ],
      };
    }
  );

  return mcp;
}

// --- MCP endpoint (Streamable HTTP) --------------------------------------
app.post('/mcp', requireSession, async (req, res) => {
  const mcp = buildMcpServer(req.sessionId);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => transport.close());
  await mcp.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// Stateless server: GET/DELETE aren't supported, but must still return a
// well-formed JSON-RPC error instead of falling through to Express's default
// HTML 404 — some MCP clients hard-fail if the response isn't valid JSON.
app.get('/mcp', (req, res) => {
  res.status(405).json({
    jsonrpc: '2.0',
    error: { code: -32000, message: 'Method not allowed.' },
    id: null,
  });
});

app.delete('/mcp', (req, res) => {
  res.status(405).json({
    jsonrpc: '2.0',
    error: { code: -32000, message: 'Method not allowed.' },
    id: null,
  });
});

// ---------------------------------------------------------------------------
// Hosted viewer page + its token-exchange endpoint
// ---------------------------------------------------------------------------
app.get('/api/viewer-session', async (req, res) => {
  const { session } = req.query;
  try {
    const { urn } = jwt.verify(session, JWT_SECRET);
    const accessToken = await get2LeggedViewerToken();
    res.json({ urn, accessToken });
  } catch {
    res.status(400).json({ error: 'Invalid or expired viewer session link.' });
  }
});

app.get('/viewer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'viewer.html'));
});

app.listen(PORT, () => {
  console.log(`ACC MCP server listening on port ${PORT}`);
  console.log(`Public URL should be: ${PUBLIC_BASE_URL}`);
});
