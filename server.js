require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { registerAppTool, registerAppResource, RESOURCE_MIME_TYPE } = require('@modelcontextprotocol/ext-apps/server');
const { z } = require('zod');

const VIEWER_APP_RESOURCE_URI = 'ui://acc-viewer/mcp-app-viewer.html';
const AUTODESK_DOMAINS = ['https://developer.api.autodesk.com', 'https://*.autodesk.com'];

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

async function getDerivativeUrn(token, project_id, item_id) {
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
  return base64url(Buffer.from(derivativeUrn));
}

function logApsFailure(context, status, data) {
  console.error(`[APS ${context}] HTTP ${status}: ${JSON.stringify(data)}`);
}

function withErrorLogging(name, handler) {
  return async (...args) => {
    try {
      return await handler(...args);
    } catch (err) {
      if (err.response) {
        logApsFailure(name, err.response.status, err.response.data);
      } else {
        console.error(`[tool:${name}] error:`, err.message);
      }
      throw err;
    }
  };
}

async function getDefaultModelViewGuid(token, urnBase64) {
  const res = await axios.get(
    `${APS_DATA_BASE}/modelderivative/v2/designdata/${urnBase64}/metadata`,
    { headers: apsHeaders(token), validateStatus: () => true }
  );
  if (res.status >= 400) {
    logApsFailure('metadata', res.status, res.data);
    throw new Error(`Failed to fetch model views (HTTP ${res.status}): ${JSON.stringify(res.data)}`);
  }
  const views = res.data.data?.metadata || [];
  if (!views.length) throw new Error('No viewable model views found — the model may still be translating.');
  const view3d = views.find(v => v.role === '3d') || views[0];
  return view3d.guid;
}

async function getModelProperties(token, urnBase64, guid) {
  const res = await axios.get(
    `${APS_DATA_BASE}/modelderivative/v2/designdata/${urnBase64}/metadata/${guid}/properties`,
    { headers: apsHeaders(token), validateStatus: () => true }
  );
  if (res.status === 202) {
    throw new Error('Model properties are still being extracted by Autodesk — try again in a minute.');
  }
  if (res.status >= 400) {
    logApsFailure('properties', res.status, res.data);
    throw new Error(`Failed to fetch model properties (HTTP ${res.status}): ${JSON.stringify(res.data)}`);
  }
  return res.data.data?.collection || [];
}

function elementCategory(obj) {
  for (const group of Object.values(obj.properties || {})) {
    if (group && typeof group === 'object' && group.Category) return String(group.Category);
  }
  return 'Uncategorized';
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

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
    'count_model_elements',
    {
      title: 'Count model elements',
      description:
        "Get element counts from a model. Without a category, returns a breakdown of element counts across the whole model (e.g. Doors, Windows, Walls). With a category (e.g. \"Doors\"), returns the count and a sample of matching element names. Needs project_id and item_id (from list_folder_contents, where type is 'items').",
      inputSchema: {
        project_id: z.string(),
        item_id: z.string(),
        category: z.string().optional().describe('Element category to count, e.g. "Doors", "Windows", "Walls". Omit for a full breakdown by category.'),
      },
    },
    withErrorLogging('count_model_elements', async ({ project_id, item_id, category }) => {
      const token = await getValidApsAccessToken(sessionId);
      const urnBase64 = await getDerivativeUrn(token, project_id, item_id);
      const guid = await getDefaultModelViewGuid(token, urnBase64);
      const elements = await getModelProperties(token, urnBase64, guid);

      if (!category) {
        const counts = {};
        for (const el of elements) {
          const cat = elementCategory(el);
          counts[cat] = (counts[cat] || 0) + 1;
        }
        const breakdown = Object.entries(counts).sort((a, b) => b[1] - a[1]);
        return {
          content: [{ type: 'text', text: JSON.stringify({ totalElements: elements.length, byCategory: breakdown }, null, 2) }],
        };
      }

      const needle = category.toLowerCase();
      const matches = elements.filter(el => elementCategory(el).toLowerCase().includes(needle));
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              { category, count: matches.length, sample: matches.slice(0, 20).map(el => el.name) },
              null,
              2
            ),
          },
        ],
      };
    })
  );

  registerAppTool(
    mcp,
    'get_viewer_link',
    {
      title: 'Get a viewer link for a model',
      description:
        "Open a model item in an interactive 3D viewer, inline in this chat when supported (falls back to a browser link otherwise). Needs project_id and item_id (from list_folder_contents, where type is 'items').",
      inputSchema: { project_id: z.string(), item_id: z.string() },
      _meta: { ui: { resourceUri: VIEWER_APP_RESOURCE_URI } },
    },
    withErrorLogging('get_viewer_link', async ({ project_id, item_id }) => {
      const token = await getValidApsAccessToken(sessionId);
      const urnBase64 = await getDerivativeUrn(token, project_id, item_id);

      const viewerToken = jwt.sign({ urn: urnBase64, sessionId }, JWT_SECRET, { expiresIn: '15m' });
      const viewerUrl = `${PUBLIC_BASE_URL}/viewer?session=${viewerToken}`;
      return {
        content: [
          {
            type: 'text',
            text: `Opening the model in the viewer. If it doesn't render inline, open this link in a browser:\n${viewerUrl}\n\n(Link expires in 15 minutes.)`,
          },
        ],
        _meta: { urn: urnBase64 },
      };
    })
  );

  // Hidden from the model — only the viewer app UI calls this (via
  // app.callServerTool) to get a fresh, scoped token for the viewer SDK,
  // so no APS access token is ever exposed in chat/text content.
  registerAppTool(
    mcp,
    '_get_viewer_access_token',
    {
      title: 'Get viewer access token',
      description: 'Internal: fetch a short-lived access token for the model viewer UI.',
      inputSchema: {},
      _meta: { ui: { visibility: ['app'] } },
    },
    withErrorLogging('_get_viewer_access_token', async () => {
      const accessToken = await getValidApsAccessToken(sessionId);
      return { content: [{ type: 'text', text: accessToken }] };
    })
  );

  registerAppResource(
    mcp,
    'ACC Model Viewer',
    VIEWER_APP_RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async () => ({
      contents: [
        {
          uri: VIEWER_APP_RESOURCE_URI,
          mimeType: RESOURCE_MIME_TYPE,
          text: fs.readFileSync(path.join(__dirname, 'public', 'mcp-app-viewer.html'), 'utf-8'),
          _meta: {
            ui: {
              csp: {
                resourceDomains: [...AUTODESK_DOMAINS, 'https://esm.sh', 'https://*.esm.sh'],
                connectDomains: AUTODESK_DOMAINS,
              },
            },
          },
        },
      ],
    })
  );

  return mcp;
}

// --- MCP endpoint (Streamable HTTP) --------------------------------------
app.post('/mcp', requireSession, async (req, res) => {
  if (req.body?.method === 'initialize') {
    console.log('[mcp] initialize from client:', JSON.stringify(req.body.params?.clientInfo), 'capabilities:', JSON.stringify(req.body.params?.capabilities));
  }
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
    const { urn, sessionId } = jwt.verify(session, JWT_SECRET);
    const accessToken = await getValidApsAccessToken(sessionId);
    res.json({ urn, accessToken });
  } catch (err) {
    console.error('[viewer-session] error:', err.response?.data || err.message);
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
