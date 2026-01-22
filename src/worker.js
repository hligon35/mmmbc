// Cloudflare Worker (Option B scaffold)
// - Serves static site assets from ./cf_site via env.ASSETS
// - Implements gallery API + CDN endpoints using D1 + R2
//
// Auth model (Cloudflare-native): protect /admin and /api via Cloudflare Access.
// When Access is enabled, Cloudflare injects cf-access-authenticated-user-email.

function json(resBody, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(resBody), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers
    }
  });
}

function text(body, { status = 200, headers = {} } = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...headers
    }
  });
}

function sanitizeSegment(input) {
  return String(input || '')
    .trim()
    .replace(/[^a-zA-Z0-9-_ ]/g, '')
    .replace(/\s+/g, ' ')
    .slice(0, 80);
}

function splitTags(raw) {
  return String(raw || '')
    .split(',')
    .map((t) => sanitizeSegment(t).toLowerCase())
    .filter(Boolean)
    .slice(0, 25);
}

function getAccessEmail(request) {
  return (
    request.headers.get('cf-access-authenticated-user-email')
    || request.headers.get('Cf-Access-Authenticated-User-Email')
    || ''
  ).trim().toLowerCase();
}

function hasAccessSessionCookie(request) {
  const cookie = String(request.headers.get('cookie') || '');
  return (
    /(?:^|;\s*)CF_Authorization(?:_[^=]+)?=/.test(cookie)
    || /(?:^|;\s*)CF_AppSession=/.test(cookie)
  );
}

function allowList(env) {
  const raw = String(env.ADMIN_ALLOW_EMAILS || '').trim();
  if (!raw) return null;
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function isDevBypass(env) {
  const raw = String(env.DEV_BYPASS_AUTH || '').trim().toLowerCase();
  return ['1', 'true', 'yes', 'y', 'on'].includes(raw);
}

function allowServiceTokenAdmin(env) {
  const raw = String(env.ALLOW_SERVICE_TOKEN_ADMIN || '').trim().toLowerCase();
  return ['1', 'true', 'yes', 'y', 'on'].includes(raw);
}

function hasServiceTokenHeaders(request) {
  // Cloudflare Access service tokens are presented via these headers.
  // Note: we do not validate values here; Access should gate requests at the edge.
  const id = request.headers.get('CF-Access-Client-Id') || request.headers.get('cf-access-client-id') || '';
  const secret = request.headers.get('CF-Access-Client-Secret') || request.headers.get('cf-access-client-secret') || '';
  return Boolean(String(id).trim()) && Boolean(String(secret).trim());
}

function requireAdmin(request, env) {
  if (isDevBypass(env)) return { ok: true, email: 'dev@local' };

  // Allow Access Service Tokens (useful for automation/migrations) when enabled.
  if (allowServiceTokenAdmin(env) && hasServiceTokenHeaders(request)) {
    return { ok: true, email: 'service-token@access' };
  }

  const email = getAccessEmail(request);
  if (!email) return { ok: false, error: 'Unauthorized (Cloudflare Access required)' };
  const allow = allowList(env);
  if (allow && !allow.has(email)) return { ok: false, error: 'Forbidden' };
  return { ok: true, email };
}

function guessContentType(key) {
  const k = String(key || '').toLowerCase();
  if (k.endsWith('.jpg') || k.endsWith('.jpeg')) return 'image/jpeg';
  if (k.endsWith('.png')) return 'image/png';
  if (k.endsWith('.webp')) return 'image/webp';
  if (k.endsWith('.gif')) return 'image/gif';
  return 'application/octet-stream';
}

async function listGallery(env) {
  const rows = await env.DB.prepare(
    `SELECT id, album, label, tags_json, file_key, thumb_key, original_name, created_at, position
     FROM gallery_items`
  ).all();

  const items = (rows.results || []).map((r) => {
    const tags = (() => {
      try {
        const parsed = JSON.parse(r.tags_json || '[]');
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    })();

    return {
      id: r.id,
      album: r.album,
      label: r.label,
      tags,
      file: `/cdn/gallery/${encodeURI(r.file_key)}`,
      thumb: r.thumb_key ? `/cdn/gallery/${encodeURI(r.thumb_key)}` : `/cdn/gallery/${encodeURI(r.file_key)}`,
      originalName: r.original_name,
      createdAt: r.created_at,
      position: r.position
    };
  });

  return { items };
}

async function handleGalleryUpload(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const ct = request.headers.get('content-type') || '';
  if (!ct.toLowerCase().includes('multipart/form-data')) {
    return json({ error: 'Expected multipart/form-data' }, { status: 400 });
  }

  const form = await request.formData();
  const album = sanitizeSegment(form.get('album') || 'General') || 'General';
  const label = sanitizeSegment(form.get('label') || '') || '';
  const tags = splitTags(form.get('tags') || '');

  const files = form.getAll('images').filter((f) => f && typeof f === 'object' && 'arrayBuffer' in f);
  if (!files.length) return json({ error: 'No images uploaded.' }, { status: 400 });

  const added = [];
  for (const file of files) {
    const id = crypto.randomUUID();
    const originalName = String(file.name || 'image');
    const safeBase = sanitizeSegment(originalName.replace(/\.[^.]+$/, '')).replace(/\s+/g, '-') || 'image';
    const ext = (originalName.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '');
    const createdAt = new Date().toISOString();

    const fileKey = `gallery/${album}/${createdAt.slice(0, 10)}_${safeBase}_${id}.${ext || 'jpg'}`;

    // Store original in R2
    await env.GALLERY_BUCKET.put(fileKey, await file.arrayBuffer(), {
      httpMetadata: {
        contentType: file.type || guessContentType(fileKey)
      }
    });

    // No server-side thumbnail generation in Workers (sharp not available).
    // For now, thumb == original; later we can add client-generated thumbs.
    const thumbKey = null;

    await env.DB.prepare(
      `INSERT INTO gallery_items (id, album, label, tags_json, file_key, thumb_key, original_name, created_at, position)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`
    ).bind(
      id,
      album,
      label,
      JSON.stringify(tags),
      fileKey,
      thumbKey,
      originalName,
      createdAt
    ).run();

    added.push({
      id,
      album,
      label,
      tags,
      file: `/cdn/gallery/${encodeURI(fileKey)}`,
      thumb: `/cdn/gallery/${encodeURI(fileKey)}`,
      originalName,
      createdAt,
      position: null
    });
  }

  return json({ ok: true, added });
}

async function handleGalleryOrder(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const album = sanitizeSegment(body?.album || '');
  const orderedIds = Array.isArray(body?.orderedIds) ? body.orderedIds.map((x) => String(x)) : [];
  if (!album) return json({ error: 'Album is required.' }, { status: 400 });
  if (!orderedIds.length) return json({ error: 'orderedIds is required.' }, { status: 400 });

  // Transaction-like: set positions for ids in order.
  for (let i = 0; i < orderedIds.length; i += 1) {
    await env.DB.prepare(
      `UPDATE gallery_items SET position=? WHERE id=? AND album=?`
    ).bind(i, orderedIds[i], album).run();
  }

  return json({ ok: true });
}

async function handleGalleryDelete(request, env, id) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const row = await env.DB.prepare(
    `SELECT file_key, thumb_key FROM gallery_items WHERE id=?`
  ).bind(id).first();

  if (!row) return json({ error: 'Not found' }, { status: 404 });

  try {
    if (row.file_key) await env.GALLERY_BUCKET.delete(row.file_key);
    if (row.thumb_key) await env.GALLERY_BUCKET.delete(row.thumb_key);
  } catch {
    // ignore
  }

  await env.DB.prepare(`DELETE FROM gallery_items WHERE id=?`).bind(id).run();
  return json({ ok: true });
}

async function handleR2List(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const url = new URL(request.url);
  const prefix = sanitizeSegment(url.searchParams.get('prefix') || 'gallery/') || 'gallery/';
  const limitRaw = Number(url.searchParams.get('limit') || 50);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.trunc(limitRaw))) : 50;
  const cursor = String(url.searchParams.get('cursor') || '').trim() || undefined;

  const listed = await env.GALLERY_BUCKET.list({ prefix, limit, cursor });
  return json({
    ok: true,
    prefix,
    limit,
    cursor: cursor || null,
    truncated: Boolean(listed.truncated),
    nextCursor: listed.truncated ? listed.cursor : null,
    objects: (listed.objects || []).map((o) => ({
      key: o.key,
      size: o.size,
      etag: o.etag,
      uploaded: o.uploaded
    }))
  });
}

async function handleCdn(request, env) {
  const prefix = '/cdn/gallery/';
  const url = new URL(request.url);
  const key = decodeURI(url.pathname.slice(prefix.length));
  if (!key) return new Response('Not found', { status: 404 });

  const obj = await env.GALLERY_BUCKET.get(key);
  if (!obj) return new Response('Not found', { status: 404 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('Content-Type', headers.get('Content-Type') || guessContentType(key));
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');

  return new Response(obj.body, { status: 200, headers });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Admin entrypoint: send unauthenticated users to the custom login page.
    // Note: keep this narrow so that /admin/login.html can load its CSS/JS.
    if (
      request.method === 'GET'
      && (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/index.html')
      && !isDevBypass(env)
      && !getAccessEmail(request)
      && !hasAccessSessionCookie(request)
    ) {
      return Response.redirect(`${url.origin}/admin/login.html`, 302);
    }

    // CDN endpoint for gallery objects in R2
    if (url.pathname.startsWith('/cdn/gallery/')) {
      return handleCdn(request, env);
    }

    // Minimal API
    if (url.pathname === '/api/me' && request.method === 'GET') {
      const email = getAccessEmail(request);
      if (!email && !isDevBypass(env)) return json({ user: null });
      return json({ user: { id: email || 'dev', email: email || 'dev@local', role: 'admin', name: '', isMaster: false, mustOnboard: false, twoFactorEnabled: false } });
    }

    if (url.pathname === '/api/gallery' && request.method === 'GET') {
      const auth = requireAdmin(request, env);
      if (!auth.ok) return json({ error: auth.error }, { status: 401 });
      return json(await listGallery(env));
    }

    if (url.pathname === '/api/gallery/upload' && request.method === 'POST') {
      return handleGalleryUpload(request, env);
    }

    if (url.pathname === '/api/gallery/order' && request.method === 'PUT') {
      return handleGalleryOrder(request, env);
    }

    // Diagnostic: list objects in the configured R2 bucket (admin only)
    if (url.pathname === '/api/gallery/r2list' && request.method === 'GET') {
      return handleR2List(request, env);
    }

    if (url.pathname.startsWith('/api/gallery/') && request.method === 'DELETE') {
      const id = url.pathname.split('/').pop();
      return handleGalleryDelete(request, env, id);
    }

    // Health
    if (url.pathname === '/api/admin/health') {
      const auth = requireAdmin(request, env);
      if (!auth.ok) return json({ error: auth.error }, { status: 401 });
      return json({ ok: true, time: new Date().toISOString() });
    }

    // Static assets (public site + admin UI) from ./cf_site
    if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
      return text('Assets binding missing. Check wrangler.jsonc assets config.', { status: 500 });
    }

    return env.ASSETS.fetch(request);
  }
};
