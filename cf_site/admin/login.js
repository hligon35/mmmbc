(function () {
  'use strict';

  const status = document.getElementById('authStatus');
  const hint = document.getElementById('loginHint');
  const btn = document.getElementById('accessLoginBtn');

  function setStatus(t) {
    if (status) status.textContent = String(t || '');
  }

  function setHint(t) {
    if (hint) hint.textContent = String(t || '');
  }

  function buildAccessLoginUrl() {
    const origin = window.location.origin;
    const redirectUrl = `${origin}/admin/`;
    return `/cdn-cgi/access/login?redirect_url=${encodeURIComponent(redirectUrl)}`;
  }

  async function checkMe() {
    try {
      const res = await fetch('/api/me', { method: 'GET', credentials: 'same-origin', redirect: 'follow' });
      if (!res.ok) return null;
      const data = await res.json().catch(() => null);
      return data;
    } catch {
      return null;
    }
  }

  async function init() {
    setStatus('Checking Access…');
    if (btn) btn.href = buildAccessLoginUrl();

    const me = await checkMe();
    if (me && me.user) {
      setStatus(`Signed in as ${me.user.email}`);
      setHint('Redirecting to dashboard…');
      window.location.replace('/admin/');
      return;
    }

    setStatus('Not signed in');
    setHint('');
  }

  init();
})();
