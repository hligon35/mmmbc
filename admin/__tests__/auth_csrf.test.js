const fs = require('fs');
const path = require('path');
const os = require('os');
const request = require('supertest');

function mkTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe('admin auth + csrf', () => {
  let tmpData;
  let tmpSessions;
  let app;
  let boot;

  beforeAll(async () => {
    tmpData = mkTempDir('mmmbc-admin-data-');
    tmpSessions = mkTempDir('mmmbc-admin-sessions-');

    process.env.ADMIN_DATA_DIR = tmpData;
    process.env.SESSIONS_DIR = tmpSessions;
    process.env.SESSION_SECRET = 'test_session_secret_1234567890';
    process.env.ADMIN_EMAIL = 'admin@example.com';
    process.env.ADMIN_PASSWORD = 'Str0ng!Passw0rd';
    process.env.ENFORCE_HTTPS = 'false';
    process.env.SUPPORT_API_TOKEN = 'test_support_token_123';
    process.env.SUPPORT_DISABLE_SEND = 'true';

    ({ app, boot } = require('../server'));
    await boot({ listen: false });
  });

  afterAll(() => {
    try { fs.rmSync(tmpData, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(tmpSessions, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  test('requires auth for /api/csrf', async () => {
    const res = await request(app).get('/api/csrf');
    expect(res.status).toBe(401);
  });

  test('login works and CSRF is enforced', async () => {
    const agent = request.agent(app);

    // login
    const login = await agent
      .post('/api/auth/login')
      .send({ email: 'admin@example.com', password: 'Str0ng!Passw0rd' });
    expect(login.status).toBe(200);

    // get token
    const csrf = await agent.get('/api/csrf');
    expect(csrf.status).toBe(200);
    expect(typeof csrf.body.csrfToken).toBe('string');
    expect(csrf.body.csrfToken.length).toBeGreaterThan(10);

    // POST without CSRF should fail
    const bad = await agent
      .post('/api/announcements')
      .send({ title: 'Hello', body: 'World' });
    expect(bad.status).toBe(403);

    // POST with CSRF should succeed
    const ok = await agent
      .post('/api/announcements')
      .set('X-CSRF-Token', csrf.body.csrfToken)
      .send({ title: 'Hello', body: 'World' });
    expect(ok.status).toBe(200);
    expect(ok.body.ok).toBe(true);
  });

  test('support endpoint accepts SUPPORT_API_TOKEN without CSRF', async () => {
    const res = await request(app)
      .post('/api/support/message')
      .set('X-Support-Token', 'test_support_token_123')
      .set('X-Support-Actor', 'support-emailer@test')
      .send({ subject: 'Test', message: 'Hello', replyTo: 'user@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    // In tests we disable sending to avoid network calls.
    expect(res.body.disabled).toBe(true);
  });
});
