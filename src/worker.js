// Cloudflare Worker (Option B scaffold)
// - Serves static site assets from ./cf_site via env.ASSETS
// - Implements gallery API + CDN endpoints using D1 + R2
//
// Auth model (Cloudflare-native): protect /admin and /api via Cloudflare Access.
// When Access is enabled, Cloudflare injects cf-access-authenticated-user-email.

import { EmailMessage } from 'cloudflare:email';

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

function sanitizePrefix(input, { fallback = 'gallery/', ensureTrailingSlash = false } = {}) {
  const raw = String(input || '').trim();
  // Allow only path-ish characters; keep '/' so we can browse prefixes.
  let cleaned = raw.replace(/[^a-zA-Z0-9/_-]/g, '');
  cleaned = cleaned.replace(/^\/+/, '');
  if (!cleaned) cleaned = fallback;
  if (ensureTrailingSlash && !cleaned.endsWith('/')) cleaned += '/';
  return cleaned;
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

function getHeaderTrim(request, name) {
  return String(request.headers.get(name) || '').trim();
}

function hasServiceTokenHeaders(request) {
  // Cloudflare Access service tokens are presented via these headers.
  const id = getHeaderTrim(request, 'CF-Access-Client-Id') || getHeaderTrim(request, 'cf-access-client-id');
  const secret = getHeaderTrim(request, 'CF-Access-Client-Secret') || getHeaderTrim(request, 'cf-access-client-secret');
  return Boolean(id) && Boolean(secret);
}

function hasValidServiceToken(request, env) {
  // Support server-to-server auth for local admin proxying.
  // If these are set as Worker secrets/vars, we validate and allow.
  const expectedId = String(env.CF_ACCESS_CLIENT_ID || '').trim();
  const expectedSecret = String(env.CF_ACCESS_CLIENT_SECRET || '').trim();
  if (!expectedId || !expectedSecret) return false;

  const id = getHeaderTrim(request, 'CF-Access-Client-Id') || getHeaderTrim(request, 'cf-access-client-id');
  const secret = getHeaderTrim(request, 'CF-Access-Client-Secret') || getHeaderTrim(request, 'cf-access-client-secret');
  if (!id || !secret) return false;

  return id === expectedId && secret === expectedSecret;
}

function hasAccessJwtAssertion(request) {
  return Boolean(
    getHeaderTrim(request, 'cf-access-jwt-assertion')
    || getHeaderTrim(request, 'Cf-Access-Jwt-Assertion')
  );
}

function requireAdmin(request, env) {
  if (isDevBypass(env)) return { ok: true, email: 'dev@local' };

  // Strong path: validate the service token headers against Worker secrets.
  if (hasValidServiceToken(request, env)) {
    return { ok: true, email: 'service-token@access' };
  }

  // Allow Access Service Tokens (useful for automation/migrations) when enabled.
  // NOTE: If Cloudflare Access is in front of this Worker, it will validate the
  // service token at the edge and typically inject a JWT assertion header.
  // In that case we can allow without having the token values in Worker env.
  if (allowServiceTokenAdmin(env) && hasServiceTokenHeaders(request) && hasAccessJwtAssertion(request)) {
    return { ok: true, email: 'service-token@access' };
  }

  const email = getAccessEmail(request);
  if (!email) return { ok: false, error: 'Unauthorized (Cloudflare Access required)' };
  const allow = allowList(env);
  if (allow && !allow.has(email)) return { ok: false, error: 'Forbidden' };
  return { ok: true, email };
}

async function handleSupportMessage(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const body = await request.json().catch(() => null);
  const subjectRaw = String(body?.subject || '').trim();
  const messageRaw = String(body?.message || '').trim();
  const replyToRaw = String(body?.replyTo || '').trim();

  if (!subjectRaw || !messageRaw) return json({ error: 'Subject and message are required.' }, { status: 400 });

  const subject = subjectRaw.slice(0, 140);
  const message = messageRaw.slice(0, 5000);
  const replyTo = replyToRaw && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(replyToRaw) ? replyToRaw : '';

  const toEmail = String(env.SUPPORT_TO_EMAIL || 'support@hldesignedit.com').trim();
  const fromEmail = String(env.SUPPORT_FROM_EMAIL || 'no-reply@mmmbc.com').trim();
  const fromName = String(env.SUPPORT_FROM_NAME || 'MMMBC Admin Support').trim() || 'MMMBC Admin Support';

  const composedSubject = `[MMMBC Support] ${subject}`;
  const textBody = [
    `From (admin): ${auth.email}`,
    replyTo ? `Reply-To: ${replyTo}` : 'Reply-To: (not provided)',
    '',
    message
  ].join('\n');

  // Prefer Cloudflare Email Routing (send_email binding) when configured.
  // This is more reliable than the legacy MailChannels endpoint, which may reject requests.
  let emailRoutingError = '';
  if (env.SUPPORT_EMAIL && typeof env.SUPPORT_EMAIL.send === 'function') {
    const escapeQuotes = (s) => String(s || '').replace(/\\/g, '\\\\').replace(/\"/g, '\\"');
    const fromHeaderName = fromName ? `"${escapeQuotes(fromName)}" ` : '';
    const fromHeader = `${fromHeaderName}<${fromEmail}>`;
    const replyToHeader = replyTo ? `Reply-To: ${replyTo}\r\n` : '';

    // Minimal RFC-5322-ish message. Good enough for plain-text support emails.
    const raw = [
      `To: ${toEmail}`,
      `From: ${fromHeader}`,
      replyToHeader.trimEnd(),
      `Subject: ${composedSubject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      textBody
    ].filter(Boolean).join('\r\n');

    try {
      const msg = new EmailMessage(fromEmail, toEmail, raw);
      await env.SUPPORT_EMAIL.send(msg);
      return json({ ok: true });
    } catch (e) {
      // Common Cloudflare Email Routing error: destination address not verified.
      // Fall back to MailChannels when possible.
      emailRoutingError = (e && (e.stack || e.message)) ? String(e.stack || e.message) : String(e);

      if (/destination address is not a verified address/i.test(emailRoutingError)) {
        return json(
          {
            error: 'Email send failed (Email Routing): SUPPORT_TO_EMAIL is not a verified destination in Cloudflare Email Routing. Add/verify the destination address in Cloudflare Dashboard → Email → Email Routing, then retry.'
          },
          { status: 502 }
        );
      }
    }
  }

  // Fallback: MailChannels (legacy). This may return 401/403 depending on current policy.
  const payload = {
    personalizations: [{ to: [{ email: toEmail }], subject: composedSubject }],
    from: { email: fromEmail, name: fromName },
    ...(replyTo ? { reply_to: { email: replyTo } } : {}),
    content: [{ type: 'text/plain', value: textBody }]
  };

  const res = await fetch('https://api.mailchannels.net/tx/v1/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    if (res.status === 401) {
      return json(
        {
          error: 'Email send failed (401 from MailChannels). Configure Cloudflare Email Routing with a send_email binding named SUPPORT_EMAIL.'
        },
        { status: 502 }
      );
    }
    const prefix = emailRoutingError
      ? `Email Routing failed (${String(emailRoutingError).slice(0, 500)}). `
      : '';
    return json({ error: `${prefix}Email send failed (${res.status}). ${errText}`.trim().slice(0, 2000) }, { status: 502 });
  }

  return json({ ok: true });
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

async function handlePublicGallery(request, env) {
  // Public endpoint: drives the public photo gallery page.
  // Note: if your Cloudflare Access policy currently protects ALL /api paths,
  // we keep this under /public so it can remain unprotected.
  const data = await listGallery(env);
  return json(data, {
    status: 200,
    headers: {
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function splitKeyUnderPrefix(key, prefix) {
  const k = String(key || '');
  const p = String(prefix || '');
  if (!k.startsWith(p)) return null;
  const rest = k.slice(p.length);
  if (!rest) return null;
  const first = rest.split('/')[0];
  if (!first) return null;
  const isFolder = rest.includes('/') && !rest.endsWith(first);
  return { first, rest, isFolder };
}

async function handleR2Tree(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const url = new URL(request.url);
  let prefix = sanitizePrefix(url.searchParams.get('prefix') || 'gallery/', {
    fallback: 'gallery/',
    ensureTrailingSlash: true
  });
  if (!prefix.startsWith('gallery/')) prefix = 'gallery/';
  const limitRaw = Number(url.searchParams.get('limit') || 250);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.trunc(limitRaw))) : 250;
  const cursor = String(url.searchParams.get('cursor') || '').trim() || undefined;

  const listed = await env.GALLERY_BUCKET.list({ prefix, limit, cursor });
  const folders = new Map();
  const files = [];

  for (const o of (listed.objects || [])) {
    const parsed = splitKeyUnderPrefix(o.key, prefix);
    if (!parsed) continue;
    if (parsed.rest.includes('/')) {
      const folderPrefix = `${prefix}${parsed.first}/`;
      if (!folders.has(parsed.first)) {
        folders.set(parsed.first, { name: parsed.first, prefix: folderPrefix });
      }
    } else {
      files.push({
        name: parsed.first,
        key: o.key,
        size: o.size,
        etag: o.etag,
        uploaded: o.uploaded
      });
    }
  }

  const folderList = Array.from(folders.values()).sort((a, b) => a.name.localeCompare(b.name));
  files.sort((a, b) => a.name.localeCompare(b.name));

  return json({
    ok: true,
    prefix,
    limit,
    cursor: cursor || null,
    truncated: Boolean(listed.truncated),
    nextCursor: listed.truncated ? listed.cursor : null,
    folders: folderList,
    files
  });
}

async function handleR2DeleteObject(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const url = new URL(request.url);
  const key = String(url.searchParams.get('key') || '').trim();
  if (!key) return json({ error: 'key is required' }, { status: 400 });
  if (!key.startsWith('gallery/')) return json({ error: 'Only gallery/ keys can be deleted here.' }, { status: 400 });

  await env.GALLERY_BUCKET.delete(key);

  // Keep DB in sync if this key had a record.
  try {
    await env.DB.prepare(
      'DELETE FROM gallery_items WHERE file_key=? OR thumb_key=?'
    ).bind(key, key).run();
  } catch {
    // ignore
  }

  return json({ ok: true, deleted: key });
}

async function handleGallerySyncFromR2(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const url = new URL(request.url);
  let prefix = sanitizePrefix(url.searchParams.get('prefix') || 'gallery/', {
    fallback: 'gallery/',
    ensureTrailingSlash: false
  });
  if (!prefix.startsWith('gallery/')) prefix = 'gallery/';
  const limitRaw = Number(url.searchParams.get('limit') || 250);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.trunc(limitRaw))) : 250;
  const cursor = String(url.searchParams.get('cursor') || '').trim() || undefined;

  const listed = await env.GALLERY_BUCKET.list({ prefix, limit, cursor });
  const objects = listed.objects || [];

  let added = 0;
  let existing = 0;

  for (const o of objects) {
    const key = String(o.key || '');
    if (!key || key.endsWith('/')) continue;
    if (!key.startsWith('gallery/')) continue;

    const found = await env.DB.prepare(
      'SELECT id FROM gallery_items WHERE file_key=? LIMIT 1'
    ).bind(key).first();

    if (found?.id) {
      existing += 1;
      continue;
    }

    const parts = key.split('/');
    const album = sanitizeSegment(parts[1] || 'General') || 'General';
    const originalName = String(parts[parts.length - 1] || 'image');
    const createdAt = (() => {
      try {
        const d = o.uploaded ? new Date(o.uploaded) : new Date();
        return d.toISOString();
      } catch {
        return new Date().toISOString();
      }
    })();

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO gallery_items (id, album, label, tags_json, file_key, thumb_key, original_name, created_at, position)
       VALUES (?, ?, '', '[]', ?, NULL, ?, ?, NULL)`
    ).bind(id, album, key, originalName, createdAt).run();

    added += 1;
  }

  return json({
    ok: true,
    prefix,
    limit,
    cursor: cursor || null,
    processed: objects.length,
    added,
    existing,
    truncated: Boolean(listed.truncated),
    nextCursor: listed.truncated ? listed.cursor : null
  });
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

async function handleGalleryUpdate(request, env, id) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const label = sanitizeSegment(body?.label || '') || '';
  const tags = splitTags(body?.tags || '');

  const existing = await env.DB.prepare(
    `SELECT id, album, label, tags_json, file_key, thumb_key, original_name, created_at, position
     FROM gallery_items WHERE id=?`
  ).bind(String(id)).first();

  if (!existing) return json({ error: 'Not found' }, { status: 404 });

  await env.DB.prepare(
    `UPDATE gallery_items SET label=?, tags_json=? WHERE id=?`
  ).bind(label, JSON.stringify(tags), String(id)).run();

  return json({
    ok: true,
    item: {
      id: existing.id,
      album: existing.album,
      label,
      tags,
      file: `/cdn/gallery/${encodeURI(existing.file_key)}`,
      thumb: existing.thumb_key ? `/cdn/gallery/${encodeURI(existing.thumb_key)}` : `/cdn/gallery/${encodeURI(existing.file_key)}`,
      originalName: existing.original_name,
      createdAt: existing.created_at,
      position: existing.position
    }
  });
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
  let prefix = sanitizePrefix(url.searchParams.get('prefix') || 'gallery/', { fallback: 'gallery/', ensureTrailingSlash: false });
  if (!prefix.startsWith('gallery/')) prefix = 'gallery/';
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

async function handleR2Migrate(request, env) {
  const auth = requireAdmin(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  const src = env.GALLERY_BUCKET_SRC;
  const dst = env.GALLERY_BUCKET_DST;
  if (!src || !dst || typeof src.list !== 'function' || typeof src.get !== 'function' || typeof dst.put !== 'function') {
    return json({
      error: 'Migration buckets not configured. Bind GALLERY_BUCKET_SRC and GALLERY_BUCKET_DST in wrangler.jsonc.'
    }, { status: 500 });
  }

  const url = new URL(request.url);
  let prefix = sanitizePrefix(url.searchParams.get('prefix') || 'gallery/', { fallback: 'gallery/', ensureTrailingSlash: false });
  if (!prefix.startsWith('gallery/')) prefix = 'gallery/';
  const limitRaw = Number(url.searchParams.get('limit') || 100);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, Math.trunc(limitRaw))) : 100;
  const cursor = String(url.searchParams.get('cursor') || '').trim() || undefined;

  const overwrite = ['1', 'true', 'yes', 'y', 'on'].includes(String(url.searchParams.get('overwrite') || '').trim().toLowerCase());
  const dryRun = ['1', 'true', 'yes', 'y', 'on'].includes(String(url.searchParams.get('dryRun') || '').trim().toLowerCase());

  const listed = await src.list({ prefix, limit, cursor });
  const objects = listed.objects || [];

  let copied = 0;
  let skipped = 0;
  let missing = 0;
  const errors = [];

  for (const obj of objects) {
    const key = obj.key;
    try {
      if (!overwrite) {
        const existing = await dst.head(key);
        if (existing) {
          skipped += 1;
          continue;
        }
      }

      if (dryRun) {
        copied += 1;
        continue;
      }

      const srcObj = await src.get(key);
      if (!srcObj) {
        missing += 1;
        continue;
      }

      await dst.put(key, srcObj.body, {
        httpMetadata: srcObj.httpMetadata,
        customMetadata: srcObj.customMetadata
      });
      copied += 1;
    } catch (e) {
      const msg = (e && (e.stack || e.message)) ? String(e.stack || e.message) : String(e);
      errors.push({ key, error: msg.slice(0, 500) });
    }
  }

  return json({
    ok: true,
    prefix,
    limit,
    cursor: cursor || null,
    processed: objects.length,
    copied,
    skipped,
    missing,
    errors,
    truncated: Boolean(listed.truncated),
    nextCursor: listed.truncated ? listed.cursor : null
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
  const guessed = guessContentType(key);
  const ct = String(headers.get('Content-Type') || '').trim().toLowerCase();
  if (!ct || ct === 'application/octet-stream' || ct === 'binary/octet-stream') {
    headers.set('Content-Type', guessed);
  }
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

    // Public gallery feed (used by the public Photo Gallery page)
    if ((url.pathname === '/public/gallery.json' || url.pathname === '/public/gallery') && request.method === 'GET') {
      return handlePublicGallery(request, env);
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

    if (url.pathname.startsWith('/api/gallery/') && request.method === 'PUT') {
      const id = url.pathname.split('/').pop();
      return handleGalleryUpdate(request, env, id);
    }

    // Diagnostic: list objects in the configured R2 bucket (admin only)
    if (url.pathname === '/api/gallery/r2list' && request.method === 'GET') {
      return handleR2List(request, env);
    }

    // Admin-only: browse R2 objects by "folder" prefix
    if (url.pathname === '/api/gallery/r2tree' && request.method === 'GET') {
      return handleR2Tree(request, env);
    }

    // Admin-only: delete an R2 object by key (and remove DB row if any)
    if (url.pathname === '/api/gallery/r2object' && request.method === 'DELETE') {
      return handleR2DeleteObject(request, env);
    }

    // Admin-only: sync D1 gallery rows from current R2 contents (paginated)
    if (url.pathname === '/api/gallery/sync' && request.method === 'POST') {
      return handleGallerySyncFromR2(request, env);
    }

    // Admin-only: migrate/copy objects between two R2 buckets (paginated)
    // Requires wrangler bindings: GALLERY_BUCKET_SRC (source) and GALLERY_BUCKET_DST (destination)
    if (url.pathname === '/api/gallery/r2migrate' && request.method === 'GET') {
      return handleR2Migrate(request, env);
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

    // Support messages (admin only)
    if (url.pathname === '/api/support/message' && request.method === 'POST') {
      return handleSupportMessage(request, env);
    }

    // Static assets (public site + admin UI) from ./cf_site
    if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
      return text('Assets binding missing. Check wrangler.jsonc assets config.', { status: 500 });
    }

    // Avoid stale admin assets at the edge during frequent updates.
    const assetRes = await env.ASSETS.fetch(request);
    if (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname.startsWith('/admin/')) {
      const headers = new Headers(assetRes.headers);
      headers.set('Cache-Control', 'no-store');
      return new Response(assetRes.body, { status: assetRes.status, headers });
    }
    return assetRes;
  }
};
