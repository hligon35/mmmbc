async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    credentials: 'same-origin',
    ...options
  });
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? await res.json() : null;
  if (!res.ok) {
    const msg = data?.error || `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

function $(id) { return document.getElementById(id); }

function confirmWrite(message) {
  return confirm(message || 'Save changes?');
}

function uniqStringsLower(list) {
  const out = [];
  const seen = new Set();
  for (const raw of (list || [])) {
    const v = String(raw || '').trim().toLowerCase();
    if (!v) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function toTime24(hour12, minute, ampm) {
  const h = Number(hour12);
  const m = String(minute || '').padStart(2, '0');
  const a = String(ampm || '').toUpperCase();
  if (!h || h < 1 || h > 12) return '';
  if (!/^\d{2}$/.test(m)) return '';
  if (a !== 'AM' && a !== 'PM') return '';

  let hour = h % 12;
  if (a === 'PM') hour += 12;
  return `${String(hour).padStart(2, '0')}:${m}`;
}

function fromTime24(value) {
  const t = String(value || '').trim();
  const m = t.match(/^([0-2]\d):([0-5]\d)/);
  if (!m) return null;
  const hour24 = Number(m[1]);
  const minute = m[2];
  if (!Number.isFinite(hour24)) return null;
  const ampm = hour24 >= 12 ? 'PM' : 'AM';
  const hour12 = hour24 % 12 === 0 ? 12 : hour24 % 12;
  return { hour12: String(hour12), minute, ampm };
}

function initTimePicker(pickerId, hiddenInputId, { required, defaultValue } = {}) {
  const root = $(pickerId);
  const hidden = $(hiddenInputId);
  if (!root || !hidden) return;

  root.innerHTML = '';

  const hour = document.createElement('select');
  hour.className = 'select';
  hour.setAttribute('aria-label', 'Hour');

  const minute = document.createElement('select');
  minute.className = 'select';
  minute.setAttribute('aria-label', 'Minutes');

  const ampm = document.createElement('select');
  ampm.className = 'select';
  ampm.setAttribute('aria-label', 'AM/PM');

  const addOption = (sel, val, label) => {
    const opt = document.createElement('option');
    opt.value = val;
    opt.textContent = label;
    sel.appendChild(opt);
  };

  if (!required) {
    addOption(hour, '', 'Hour');
    addOption(minute, '', 'Min');
    addOption(ampm, '', 'AM/PM');
  }

  for (let h = 1; h <= 12; h += 1) addOption(hour, String(h), String(h));
  for (const mm of ['00', '15', '30', '45']) addOption(minute, mm, mm);
  addOption(ampm, 'AM', 'AM');
  addOption(ampm, 'PM', 'PM');

  root.appendChild(hour);
  root.appendChild(minute);
  root.appendChild(ampm);

  const syncToHidden = () => {
    const v = toTime24(hour.value, minute.value, ampm.value);
    hidden.value = v;
  };

  const syncFromHidden = () => {
    const parsed = fromTime24(hidden.value);
    if (!parsed) return;
    hour.value = parsed.hour12;
    minute.value = parsed.minute;
    ampm.value = parsed.ampm;
  };

  hour.addEventListener('change', syncToHidden);
  minute.addEventListener('change', syncToHidden);
  ampm.addEventListener('change', syncToHidden);

  // Initialize
  if (hidden.value) {
    syncFromHidden();
    syncToHidden();
  } else if (defaultValue) {
    hidden.value = String(defaultValue);
    syncFromHidden();
    syncToHidden();
  } else {
    syncToHidden();
  }

  const form = root.closest('form');
  if (form && !form.dataset.timePickersWired) {
    form.addEventListener('reset', () => {
      // Let the browser reset other fields first.
      setTimeout(() => {
        if (defaultValue) {
          hidden.value = String(defaultValue);
          syncFromHidden();
          syncToHidden();
        } else {
          hidden.value = '';
          if (!required) {
            hour.value = '';
            minute.value = '';
            ampm.value = '';
          }
          syncToHidden();
        }
      }, 0);
    });
    form.dataset.timePickersWired = '1';
  }
}

function getInitials(user) {
  const name = String(user?.name || '').trim();
  if (name) {
    const parts = name.split(/\s+/).filter(Boolean);
    const a = parts[0]?.[0] || 'A';
    const b = parts[1]?.[0] || '';
    return (a + b).toUpperCase();
  }
  const email = String(user?.email || '').trim();
  if (!email) return 'A';
  return String(email[0] || 'A').toUpperCase();
}

function passwordScore(pw) {
  const p = String(pw || '');
  let score = 0;
  if (p.length >= 8) score += 1;
  if (/[A-Z]/.test(p)) score += 1;
  if (/[^A-Za-z0-9]/.test(p)) score += 1;
  if (p.length >= 12) score += 1;
  return score;
}

function passwordPolicyError(pw) {
  const p = String(pw || '');
  if (p.length < 8) return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(p)) return 'Password must include at least 1 capital letter.';
  if (!/[^A-Za-z0-9]/.test(p)) return 'Password must include at least 1 special character.';
  return '';
}

function wirePeekButtons() {
  const buttons = Array.from(document.querySelectorAll('[data-peek-target]'));
  for (const btn of buttons) {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-peek-target');
      const input = targetId ? document.getElementById(targetId) : null;
      if (!input) return;
      const isPassword = input.getAttribute('type') === 'password';
      input.setAttribute('type', isPassword ? 'text' : 'password');
      btn.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
      btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      input.focus();
      try { input.setSelectionRange(input.value.length, input.value.length); } catch { /* ignore */ }
    });
  }
}

function wirePasswordMeter(inputId, meterId, textId) {
  const input = $(inputId);
  const meter = $(meterId);
  const text = $(textId);
  if (!input || !meter || !text) return;

  const update = () => {
    const score = passwordScore(input.value);
    meter.value = score;
    const label = score <= 1 ? 'Weak' : score === 2 ? 'Fair' : score === 3 ? 'Good' : 'Strong';
    text.textContent = `Password strength: ${label}`;
  };
  if (!input.dataset.meterWired) {
    input.addEventListener('input', update);
    input.dataset.meterWired = '1';
  }
  update();
}

function setTab(activeId) {
  const tabButtons = [
    $('tabBtn-photos'),
    $('tabBtn-stream'),
    $('tabBtn-events'),
    $('tabBtn-content'),
    $('tabBtn-settings'),
    $('tabBtn-account')
  ];
  const panels = [
    $('tab-photos'),
    $('tab-stream'),
    $('tab-events'),
    $('tab-content'),
    $('tab-settings'),
    $('tab-account')
  ];

  tabButtons.forEach((b) => {
    const isActive = b.getAttribute('aria-controls') === activeId;
    b.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  panels.forEach((p) => {
    p.hidden = p.id !== activeId;
  });
}

async function refreshAuthUI() {
  const me = await api('/api/me', { method: 'GET' });
  const loggedIn = !!me.user;

  const inviteToken = getInviteTokenFromHash();
  const inInviteFlow = !!inviteToken;

  $('inviteCard').hidden = !inInviteFlow;
  $('loginCard').hidden = loggedIn || inInviteFlow;
  $('dashboardCard').hidden = !loggedIn || inInviteFlow;
  $('logoutBtn').hidden = !loggedIn;
  $('accountBtn').hidden = !loggedIn;
  $('authStatus').textContent = loggedIn ? `Signed in as ${me.user.email}` : 'Not signed in';

  if (loggedIn) {
    $('salutation').textContent = `Welcome, ${me.user.name || me.user.email}`;
    $('avatarText').textContent = getInitials(me.user);

    const accountForm = $('accountForm');
    if (accountForm) {
      accountForm.elements.namedItem('name').value = String(me.user.name || '');
      accountForm.elements.namedItem('email').value = String(me.user.email || '');
    }

    const accountNote = $('accountNote');
    if (accountNote) {
      accountNote.textContent = me.user.isMaster
        ? 'Master admin email/password are controlled by server environment variables.'
        : 'Update your profile and password.';
    }
  }

  if (loggedIn) {
    await loadAll();
    applyHashNavigation();
  }

  if (inInviteFlow) {
    await loadInvite(inviteToken);
  }
}

async function login(email, password, twoFactorCode) {
  const code = String(twoFactorCode || '').trim();
  await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email,
      password,
      ...(code ? { twoFactorCode: code } : {})
    })
  });
}

async function logout() {
  await api('/api/auth/logout', { method: 'POST', body: '{}' });
}

function formatDate(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function normalizeHash() {
  return String(window.location.hash || '').replace(/^#/, '').trim().toLowerCase();
}

function getInviteTokenFromHash() {
  const raw = String(window.location.hash || '').replace(/^#/, '').trim();
  const m = raw.match(/(?:^|&)invite=([^&]+)/i);
  if (!m) return '';
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}

function applyHashNavigation() {
  const h = normalizeHash();
  if (!h) return;

  if (/invite=/.test(h)) return;

  if (h === 'photos') setTab('tab-photos');
  if (h === 'stream') setTab('tab-stream');
  if (h === 'events') setTab('tab-events');
  if (h === 'content') {
    setTab('tab-content');
    setContentSubTab('panel-content-announcements');
  }
  if (h === 'settings') {
    setTab('tab-settings');
    setSettingsSubTab('panel-settings-users');
  }
  if (h === 'account') setTab('tab-account');

  if (h === 'announcements') {
    setTab('tab-content');
    setContentSubTab('panel-content-announcements');
  }

  if (h === 'bulletins') {
    setTab('tab-content');
    setContentSubTab('panel-content-bulletins');
  }
}

function setSubTab(buttonIds, panelIds, activePanelId) {
  for (const bid of buttonIds) {
    const b = $(bid);
    if (!b) continue;
    const isActive = b.getAttribute('aria-controls') === activePanelId;
    b.setAttribute('aria-selected', isActive ? 'true' : 'false');
  }
  for (const pid of panelIds) {
    const p = $(pid);
    if (!p) continue;
    p.hidden = pid !== activePanelId;
  }
}

function setContentSubTab(panelId) {
  setSubTab(
    ['subTabBtn-content-announcements', 'subTabBtn-content-bulletins'],
    ['panel-content-announcements', 'panel-content-bulletins'],
    panelId
  );
}

function setSettingsSubTab(panelId) {
  setSubTab(
    ['subTabBtn-settings-users', 'subTabBtn-settings-social', 'subTabBtn-settings-theme'],
    ['panel-settings-users', 'panel-settings-social', 'panel-settings-theme'],
    panelId
  );
}

let inviteLoadedToken = '';
async function loadInvite(token) {
  if (!token) return;
  if (inviteLoadedToken === token) return;
  inviteLoadedToken = token;

  $('inviteError').hidden = true;
  $('inviteHint').textContent = 'Loading…';

  try {
    const data = await api(`/api/invites/${encodeURIComponent(token)}`, { method: 'GET' });
    $('inviteEmail').textContent = `Setting up: ${data.email}`;
    const qr = $('inviteQr');
    if (qr && data.twoFactor?.qrDataUrl) qr.src = data.twoFactor.qrDataUrl;
    $('inviteSecret').textContent = String(data.twoFactor?.secret || '');
    $('inviteHint').textContent = 'Scan the QR code, then complete the form.';
    wirePasswordMeter('inviteNewPassword', 'invitePwMeter', 'invitePwText');
  } catch (err) {
    $('inviteError').textContent = err.message;
    $('inviteError').hidden = false;
    $('inviteHint').textContent = '';
  }
}

// -------- Photo Gallery --------
let galleryItems = [];

function applyPhotoFilters() {
  const sort = $('photoSort').value;
  const albumFilter = $('photoAlbumFilter').value.trim().toLowerCase();
  const tagFilter = $('photoTagFilter').value.trim().toLowerCase();

  let items = [...galleryItems];
  if (albumFilter) items = items.filter((i) => String(i.album || '').toLowerCase().includes(albumFilter));
  if (tagFilter) items = items.filter((i) => (i.tags || []).some((t) => String(t).toLowerCase().includes(tagFilter)));

  items.sort((a, b) => {
    if (sort === 'name-asc') return String(a.originalName).localeCompare(String(b.originalName));
    if (sort === 'name-desc') return String(b.originalName).localeCompare(String(a.originalName));
    if (sort === 'date-asc') return String(a.createdAt).localeCompare(String(b.createdAt));
    return String(b.createdAt).localeCompare(String(a.createdAt));
  });

  renderPhotoGrid(items);
}

function renderPhotoGrid(items) {
  const grid = $('photoGrid');
  grid.innerHTML = '';

  if (!items.length) {
    grid.innerHTML = '<div class="muted">No photos yet.</div>';
    return;
  }

  for (const item of items) {
    const card = document.createElement('div');
    card.className = 'thumb';

    const img = document.createElement('img');
    img.className = 'thumb__img';
    img.src = item.thumb || item.file;
    img.alt = item.label ? `${item.label} photo` : 'Gallery photo';
    img.loading = 'lazy';

    const meta = document.createElement('div');
    meta.className = 'thumb__meta';

    const label = document.createElement('div');
    label.className = 'thumb__label';
    label.textContent = item.label || item.album || 'Photo';

    const small = document.createElement('div');
    small.className = 'thumb__small';
    small.textContent = `${item.album || 'General'} • ${formatDate(item.createdAt)}`;

    const tags = document.createElement('div');
    tags.className = 'thumb__small';
    tags.textContent = (item.tags || []).length ? `Tags: ${(item.tags || []).join(', ')}` : '';

    const actions = document.createElement('div');
    actions.className = 'row__actions';

    const del = document.createElement('button');
    del.className = 'btn';
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      if (!confirm('Delete this photo?')) return;
      await api(`/api/gallery/${item.id}`, { method: 'DELETE' });
      await loadGallery();
    });

    actions.appendChild(del);

    meta.appendChild(label);
    meta.appendChild(small);
    meta.appendChild(tags);
    meta.appendChild(actions);

    card.appendChild(img);
    card.appendChild(meta);

    grid.appendChild(card);
  }
}

async function loadGallery() {
  const data = await api('/api/gallery', { method: 'GET' });
  galleryItems = data.items || [];
  applyPhotoFilters();
}

// -------- Announcements --------
let announcementPosts = [];

function renderAnnouncements() {
  const root = $('announceList');
  root.innerHTML = '';

  for (const post of announcementPosts) {
    const row = document.createElement('div');
    row.className = 'row';

    const main = document.createElement('div');
    main.className = 'row__main';
    const t = document.createElement('div');
    t.className = 'row__title';
    t.textContent = post.title;
    const meta = document.createElement('div');
    meta.className = 'row__meta';
    const created = post.createdAt ? `Posted: ${formatDate(post.createdAt)}` : '';
    const expires = post.expiresAt ? ` • Expires: ${formatDate(post.expiresAt)}` : ' • Expires: Never';
    meta.textContent = `${created}${expires}`.trim();

    const body = document.createElement('div');
    body.className = 'row__meta';
    body.textContent = post.body;

    main.appendChild(t);
    main.appendChild(meta);
    main.appendChild(body);

    const actions = document.createElement('div');
    actions.className = 'row__actions';
    const del = document.createElement('button');
    del.className = 'btn';
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      if (!confirm('Delete this announcement?')) return;
      await api(`/api/announcements/${post.id}`, { method: 'DELETE' });
      await loadAnnouncements();
    });

    actions.appendChild(del);
    row.appendChild(main);
    row.appendChild(actions);
    root.appendChild(row);
  }

  if (!announcementPosts.length) root.innerHTML = '<div class="muted">No announcements yet.</div>';
}

async function loadAnnouncements() {
  const data = await api('/api/announcements', { method: 'GET' });
  announcementPosts = data.posts || [];
  renderAnnouncements();
}

// -------- Events --------
let events = [];
let editingEventId = null;

function normalizeTimeValue(value) {
  const t = String(value || '').trim();
  if (!t) return '';
  // Accept HH:MM or HH:MM:SS from some browsers
  const m = t.match(/^([0-2]\d):([0-5]\d)/);
  return m ? `${m[1]}:${m[2]}` : '';
}

function renderEvents() {
  const root = $('eventList');
  root.innerHTML = '';

  for (const ev of events) {
    const row = document.createElement('div');
    row.className = 'row';

    const main = document.createElement('div');
    main.className = 'row__main';
    if (editingEventId === ev.id) {
      const titleLabel = document.createElement('label');
      titleLabel.className = 'label';
      titleLabel.textContent = 'Title';
      const titleInput = document.createElement('input');
      titleInput.className = 'input';
      titleInput.type = 'text';
      titleInput.value = ev.title || '';
      titleLabel.appendChild(titleInput);

      const dateLabel = document.createElement('label');
      dateLabel.className = 'label';
      dateLabel.textContent = 'Date';
      const dateInput = document.createElement('input');
      dateInput.className = 'input';
      dateInput.type = 'date';
      dateInput.value = ev.date || '';
      dateLabel.appendChild(dateInput);

      const timeLabel = document.createElement('label');
      timeLabel.className = 'label';
      timeLabel.textContent = 'Time';
      const timeInput = document.createElement('input');
      timeInput.className = 'input';
      timeInput.type = 'time';
      timeInput.value = normalizeTimeValue(ev.time);
      timeLabel.appendChild(timeInput);

      main.appendChild(titleLabel);
      main.appendChild(dateLabel);
      main.appendChild(timeLabel);
    } else {
      const t = document.createElement('div');
      t.className = 'row__title';
      t.textContent = ev.title;
      const meta = document.createElement('div');
      meta.className = 'row__meta';
      meta.textContent = `${ev.date}${ev.time ? ` • ${ev.time}` : ''}`;

      main.appendChild(t);
      main.appendChild(meta);
    }

    const actions = document.createElement('div');
    actions.className = 'row__actions';

    if (editingEventId === ev.id) {
      const save = document.createElement('button');
      save.className = 'btn btn--primary';
      save.type = 'button';
      save.textContent = 'Save';
      save.addEventListener('click', async () => {
        const inputs = main.querySelectorAll('input');
        const title = inputs[0]?.value || '';
        const date = inputs[1]?.value || '';
        const time = inputs[2]?.value || '';

        if (!confirmWrite('Save changes to this event?')) return;

        await api(`/api/events/${ev.id}`, {
          method: 'PUT',
          body: JSON.stringify({ title, date, time })
        });
        editingEventId = null;
        await loadEvents();
      });

      const cancel = document.createElement('button');
      cancel.className = 'btn';
      cancel.type = 'button';
      cancel.textContent = 'Cancel';
      cancel.addEventListener('click', () => {
        editingEventId = null;
        renderEvents();
      });

      actions.appendChild(save);
      actions.appendChild(cancel);
    } else {
      const edit = document.createElement('button');
      edit.className = 'btn';
      edit.type = 'button';
      edit.textContent = 'Edit';
      edit.addEventListener('click', () => {
        editingEventId = ev.id;
        renderEvents();
      });
      actions.appendChild(edit);
    }

    const del = document.createElement('button');
    del.className = 'btn';
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      if (!confirm('Delete this event?')) return;
      await api(`/api/events/${ev.id}`, { method: 'DELETE' });
      if (editingEventId === ev.id) editingEventId = null;
      await loadEvents();
    });

    actions.appendChild(del);
    row.appendChild(main);
    row.appendChild(actions);
    root.appendChild(row);
  }

  if (!events.length) root.innerHTML = '<div class="muted">No events yet.</div>';
}

async function loadEvents() {
  const data = await api('/api/events', { method: 'GET' });
  events = data.events || [];
  if (editingEventId && !events.some((e) => e.id === editingEventId)) {
    editingEventId = null;
  }
  renderEvents();
}

// -------- Bulletins --------
let bulletins = [];

function toLocalDateTimeValue(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const d = new Date(t);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function isActiveBulletin(b) {
  const start = b?.startsAt ? Date.parse(b.startsAt) : NaN;
  const end = b?.endsAt ? Date.parse(b.endsAt) : NaN;
  const now = Date.now();
  if (!Number.isNaN(start) && now < start) return false;
  if (!Number.isNaN(end) && now >= end) return false;
  if (Number.isNaN(start) && Number.isNaN(end)) return false;
  return true;
}

function renderBulletins() {
  const root = $('bulletinList');
  root.innerHTML = '';

  for (const b of bulletins) {
    const row = document.createElement('div');
    row.className = 'row';

    const main = document.createElement('div');
    main.className = 'row__main';
    const t = document.createElement('div');
    t.className = 'row__title';
    t.textContent = `${b.title || 'Bulletin'} • ${b.originalName || ''}`.trim();
    const meta = document.createElement('div');
    meta.className = 'row__meta';
    const active = isActiveBulletin(b);
    meta.textContent = `${active ? 'Active now' : ''}${active ? ' • ' : ''}${toLocalDateTimeValue(b.startsAt)} → ${toLocalDateTimeValue(b.endsAt)}`;

    main.appendChild(t);
    main.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'row__actions';

    const open = document.createElement('a');
    open.className = 'btn';
    open.href = b.url;
    open.target = '_blank';
    open.rel = 'noopener noreferrer';
    open.textContent = 'Open';

    const del = document.createElement('button');
    del.className = 'btn';
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      if (!confirm('Delete this bulletin?')) return;
      await api(`/api/bulletins/${b.id}`, { method: 'DELETE' });
      await loadBulletins();
    });

    actions.appendChild(open);
    actions.appendChild(del);

    row.appendChild(main);
    row.appendChild(actions);
    root.appendChild(row);
  }

  if (!bulletins.length) root.innerHTML = '<div class="muted">No bulletins scheduled yet.</div>';
}

async function loadBulletins() {
  const data = await api('/api/bulletins', { method: 'GET' });
  bulletins = data.bulletins || [];
  renderBulletins();
}

// -------- Users --------
let users = [];

function renderUsers() {
  const root = $('userList');
  root.innerHTML = '';

  for (const u of users) {
    const row = document.createElement('div');
    row.className = 'row';

    const main = document.createElement('div');
    main.className = 'row__main';
    const t = document.createElement('div');
    t.className = 'row__title';
    t.textContent = u.email + (u.isMaster ? ' (master)' : '');
    const meta = document.createElement('div');
    meta.className = 'row__meta';
    meta.textContent = u.createdAt ? formatDate(u.createdAt) : '';

    main.appendChild(t);
    main.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'row__actions';

    if (!u.isMaster) {
      const del = document.createElement('button');
      del.className = 'btn';
      del.type = 'button';
      del.textContent = 'Delete';
      del.addEventListener('click', async () => {
        if (!confirm('Delete this admin account?')) return;
        await api(`/api/users/${u.id}`, { method: 'DELETE' });
        await loadUsers();
      });
      actions.appendChild(del);
    }

    row.appendChild(main);
    row.appendChild(actions);
    root.appendChild(row);
  }

  if (!users.length) root.innerHTML = '<div class="muted">No users.</div>';
}

async function loadUsers() {
  const data = await api('/api/users', { method: 'GET' });
  users = data.users || [];
  renderUsers();
}

// -------- Livestream --------
let livestream = null;

function getSelectedLivePlatforms() {
  const inputs = Array.from(document.querySelectorAll('input[name="livePlatforms"]'));
  return uniqStringsLower(inputs.filter((i) => i.checked).map((i) => i.value));
}

function setSelectedLivePlatforms(platforms) {
  const set = new Set(uniqStringsLower(platforms));
  const inputs = Array.from(document.querySelectorAll('input[name="livePlatforms"]'));
  for (const el of inputs) el.checked = set.has(String(el.value || '').toLowerCase());
}

function renderLivestream() {
  $('ytEmbed').value = livestream?.embeds?.youtube || '';
  $('fbEmbed').value = livestream?.embeds?.facebook || '';
  $('siteEmbed').value = livestream?.embeds?.website || '';
  $('activePlatform').value = livestream?.active?.platform || 'website';

  const activePlatforms = (livestream?.active?.platforms && Array.isArray(livestream.active.platforms))
    ? livestream.active.platforms
    : [livestream?.active?.platform || 'website'];
  setSelectedLivePlatforms(activePlatforms);

  const isLive = (livestream?.active?.status || 'offline') === 'live';
  const chip = $('liveStatus');
  chip.textContent = isLive ? 'Live' : 'Offline';
  chip.classList.toggle('statusChip--live', isLive);

  const list = $('recurringList');
  list.innerHTML = '';

  for (const r of (livestream?.recurring || [])) {
    const row = document.createElement('div');
    row.className = 'row';

    const main = document.createElement('div');
    main.className = 'row__main';
    const t = document.createElement('div');
    t.className = 'row__title';
    t.textContent = `${r.label}`;
    const meta = document.createElement('div');
    meta.className = 'row__meta';
    meta.textContent = `${r.day} • ${r.time}`;
    main.appendChild(t);
    main.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'row__actions';
    const del = document.createElement('button');
    del.className = 'btn';
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      if (!confirm('Delete this recurring stream?')) return;
      livestream.recurring = (livestream.recurring || []).filter((x) => x.id !== r.id);
      await saveLivestream();
    });

    actions.appendChild(del);
    row.appendChild(main);
    row.appendChild(actions);
    list.appendChild(row);
  }

  if (!(livestream?.recurring || []).length) {
    list.innerHTML = '<div class="muted">No recurring streams set.</div>';
  }
}

async function loadLivestream() {
  livestream = await api('/api/livestream', { method: 'GET' });
  renderLivestream();
}

async function saveLivestream() {
  const payload = {
    active: livestream.active,
    embeds: {
      youtube: $('ytEmbed').value.trim(),
      facebook: $('fbEmbed').value.trim(),
      website: $('siteEmbed').value.trim()
    },
    recurring: livestream.recurring || []
  };
  const res = await api('/api/livestream', { method: 'PUT', body: JSON.stringify(payload) });
  livestream = res.data;
  renderLivestream();
}

// -------- Settings --------
let settings = null;

async function loadSettings() {
  settings = await api('/api/settings', { method: 'GET' });

  $('socialForm').facebook.value = settings?.social?.facebook || '';
  $('socialForm').youtube.value = settings?.social?.youtube || '';
  $('socialForm').email.value = settings?.social?.email || '';
  $('socialForm').phone.value = settings?.social?.phone || '';
  $('socialForm').address.value = settings?.social?.address || '';

  $('themeForm').accent.value = settings?.theme?.accent || '#c46123';
  $('themeForm').text.value = settings?.theme?.text || '#ffffff';
  $('themeForm').background.value = settings?.theme?.background || '#000000';

  // Sync hex fields
  const a = $('themeForm').accent.value;
  const t = $('themeForm').text.value;
  const b = $('themeForm').background.value;
  if ($('themeAccentHex')) $('themeAccentHex').value = a;
  if ($('themeTextHex')) $('themeTextHex').value = t;
  if ($('themeBackgroundHex')) $('themeBackgroundHex').value = b;

  applyThemePreviewCard({ accent: a, text: t, background: b });
}

async function saveSettingsPatch(patch) {
  const res = await api('/api/settings', { method: 'PUT', body: JSON.stringify(patch) });
  settings = res.data;
  await loadSettings();
}

function normalizeHex(value) {
  const v = String(value || '').trim();
  if (!v) return '';
  const withHash = v.startsWith('#') ? v : `#${v}`;
  if (/^#[0-9a-fA-F]{6}$/.test(withHash)) return withHash.toLowerCase();
  return '';
}

function getThemeFromInputs() {
  const accent = String($('themeForm').accent.value || '#c46123');
  const text = String($('themeForm').text.value || '#ffffff');
  const background = String($('themeForm').background.value || '#000000');
  return { accent, text, background };
}

function applyThemePreviewCard(theme) {
  const card = $('themePreviewCard');
  if (!card) return;
  card.style.setProperty('--mmmbc-accent', theme.accent);
  card.style.setProperty('--mmmbc-text', theme.text);
  card.style.setProperty('--mmmbc-bg', theme.background);
}

// -------- Load everything --------
async function loadAll() {
  await Promise.all([
    loadGallery(),
    loadAnnouncements(),
    loadEvents(),
    loadBulletins(),
    loadUsers(),
    loadLivestream(),
    loadSettings()
  ]);
}

// -------- Wire UI --------
document.addEventListener('DOMContentLoaded', () => {
  // Tabs
  $('tabBtn-photos').addEventListener('click', () => setTab('tab-photos'));
  $('tabBtn-stream').addEventListener('click', () => setTab('tab-stream'));
  $('tabBtn-events').addEventListener('click', () => setTab('tab-events'));
  $('tabBtn-content').addEventListener('click', () => {
    setTab('tab-content');
    setContentSubTab('panel-content-announcements');
  });
  $('tabBtn-settings').addEventListener('click', () => {
    setTab('tab-settings');
    setSettingsSubTab('panel-settings-users');
  });
  $('tabBtn-account').addEventListener('click', () => setTab('tab-account'));

  // Sub-tabs
  if ($('subTabBtn-content-announcements')) {
    $('subTabBtn-content-announcements').addEventListener('click', () => setContentSubTab('panel-content-announcements'));
  }
  if ($('subTabBtn-content-bulletins')) {
    $('subTabBtn-content-bulletins').addEventListener('click', () => setContentSubTab('panel-content-bulletins'));
  }
  if ($('subTabBtn-settings-users')) {
    $('subTabBtn-settings-users').addEventListener('click', () => setSettingsSubTab('panel-settings-users'));
  }
  if ($('subTabBtn-settings-social')) {
    $('subTabBtn-settings-social').addEventListener('click', () => setSettingsSubTab('panel-settings-social'));
  }
  if ($('subTabBtn-settings-theme')) {
    $('subTabBtn-settings-theme').addEventListener('click', () => setSettingsSubTab('panel-settings-theme'));
  }

  // Header avatar
  $('accountBtn').addEventListener('click', () => {
    setTab('tab-account');
    window.location.hash = '#account';
  });

  // Password peek + meters
  wirePeekButtons();
  wirePasswordMeter('recoverNewPassword', 'recoverPwMeter', 'recoverPwText');
  wirePasswordMeter('newPassword', 'accountPwMeter', 'accountPwText');
  // Optional: user creation temp password uses policy checks; meter not shown in UI.

  // Login
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('loginError').hidden = true;

    const fd = new FormData(e.currentTarget);
    try {
      await login(String(fd.get('email')), String(fd.get('password')), String(fd.get('twoFactorCode') || ''));
      await refreshAuthUI();
    } catch (err) {
      $('loginError').textContent = err.message;
      $('loginError').hidden = false;
    }
  });

  // Invite onboarding
  $('copySecretBtn').addEventListener('click', async () => {
    const text = String($('inviteSecret').textContent || '');
    try {
      await navigator.clipboard.writeText(text);
      $('inviteHint').textContent = 'Copied.';
    } catch {
      $('inviteHint').textContent = 'Copy failed. You can select and copy manually.';
    }
  });

  $('inviteForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('inviteError').hidden = true;
    const token = getInviteTokenFromHash();
    if (!token) {
      $('inviteError').textContent = 'Missing invite token.';
      $('inviteError').hidden = false;
      return;
    }

    const hint = $('inviteHint');
    hint.textContent = '';
    const fd = new FormData(e.currentTarget);
    const newPassword = String(fd.get('newPassword') || '');
    const confirmPassword = String(fd.get('confirmPassword') || '');
    if (newPassword !== confirmPassword) {
      hint.textContent = 'Passwords do not match.';
      return;
    }
    const policyErr = passwordPolicyError(newPassword);
    if (policyErr) {
      hint.textContent = policyErr;
      return;
    }

    hint.textContent = 'Completing setup…';
    try {
      await api(`/api/invites/${encodeURIComponent(token)}/complete`, {
        method: 'POST',
        body: JSON.stringify({
          name: String(fd.get('name') || ''),
          newPassword,
          twoFactorCode: String(fd.get('twoFactorCode') || '')
        })
      });
      window.location.hash = '';
      inviteLoadedToken = '';
      await refreshAuthUI();
    } catch (err) {
      $('inviteError').textContent = err.message;
      $('inviteError').hidden = false;
      hint.textContent = '';
    }
  });

  // Forgot login (recovery)
  $('forgotToggle').addEventListener('click', () => {
    const panel = $('forgotPanel');
    panel.hidden = !panel.hidden;
    if (!panel.hidden) {
      const emailEl = panel.querySelector('input[name="email"]');
      if (emailEl) emailEl.focus();
    }
  });

  $('recoverForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('recoverHint');
    hint.textContent = '';
    const fd = new FormData(e.currentTarget);
    const newPassword = String(fd.get('newPassword') || '');
    const confirmPassword = String(fd.get('confirmPassword') || '');
    if (newPassword !== confirmPassword) {
      hint.textContent = 'Passwords do not match.';
      return;
    }
    const policyErr = passwordPolicyError(newPassword);
    if (policyErr) {
      hint.textContent = policyErr;
      return;
    }
    hint.textContent = 'Resetting…';
    try {
      await api('/api/auth/recover', {
        method: 'POST',
        body: JSON.stringify({
          email: String(fd.get('email') || ''),
          recoveryCode: String(fd.get('recoveryCode') || ''),
          newPassword
        })
      });
      hint.textContent = 'Password updated. You can sign in now.';
      e.currentTarget.reset();
      $('forgotPanel').hidden = true;
    } catch (err) {
      hint.textContent = err.message;
    }
  });

  $('logoutBtn').addEventListener('click', async () => {
    await logout();
    await refreshAuthUI();
  });

  // Account profile
  $('accountForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('accountHint');
    if (!confirmWrite('Save account profile changes?')) return;
    hint.textContent = 'Saving…';
    const fd = new FormData(e.currentTarget);
    try {
      await api('/api/account', {
        method: 'PUT',
        body: JSON.stringify({
          name: String(fd.get('name') || ''),
          email: String(fd.get('email') || '')
        })
      });
      hint.textContent = 'Saved.';
      await refreshAuthUI();
    } catch (err) {
      hint.textContent = err.message;
    }
  });

  // Account password
  $('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('passwordHint');
    hint.textContent = '';
    const fd = new FormData(e.currentTarget);
    const newPassword = String(fd.get('newPassword') || '');
    const confirmPassword = String(fd.get('confirmPassword') || '');
    if (newPassword !== confirmPassword) {
      hint.textContent = 'Passwords do not match.';
      return;
    }
    const policyErr = passwordPolicyError(newPassword);
    if (policyErr) {
      hint.textContent = policyErr;
      return;
    }

    if (!confirmWrite('Update your password?')) return;

    hint.textContent = 'Updating…';
    try {
      await api('/api/account/password', {
        method: 'PUT',
        body: JSON.stringify({
          currentPassword: String(fd.get('currentPassword') || ''),
          newPassword
        })
      });
      hint.textContent = 'Password updated.';
      e.currentTarget.reset();
      wirePasswordMeter('newPassword', 'accountPwMeter', 'accountPwText');
    } catch (err) {
      hint.textContent = err.message;
    }
  });

  // Photo uploads (multipart)
  $('photoUploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const hint = $('photoUploadHint');

    if (!confirmWrite('Upload selected photo(s)?')) return;

    hint.textContent = 'Uploading…';

    const fd = new FormData(form);
    const res = await fetch('/api/gallery/upload', {
      method: 'POST',
      body: fd,
      credentials: 'same-origin'
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      hint.textContent = data.error || 'Upload failed.';
      return;
    }

    hint.textContent = `Uploaded ${data.added?.length || 0} photo(s).`;
    form.reset();
    await loadGallery();
  });

  $('photoSort').addEventListener('change', applyPhotoFilters);
  $('photoAlbumFilter').addEventListener('input', applyPhotoFilters);
  $('photoTagFilter').addEventListener('input', applyPhotoFilters);

  $('exportBtn').addEventListener('click', async () => {
    if (!confirmWrite('Export current content to website files now?')) return;
    await api('/api/export', { method: 'POST', body: '{}' });
    alert('Exported to website files (gallery.json, schedule.json, theme.css, etc).');
  });

  // Announcements
  $('announceForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('announceHint');

    if (!confirmWrite('Post this announcement?')) return;

    hint.textContent = 'Posting…';

    const fd = new FormData(e.currentTarget);
    const never = fd.get('neverExpires') === 'on';
    const expiresInDaysRaw = never ? 0 : fd.get('expiresInDays');
    await api('/api/announcements', {
      method: 'POST',
      body: JSON.stringify({
        title: fd.get('title'),
        body: fd.get('body'),
        expiresInDays: expiresInDaysRaw
      })
    });

    e.currentTarget.reset();
    hint.textContent = 'Posted.';
    await loadAnnouncements();
  });

  // Hash navigation (e.g. /admin/#announcements)
  window.addEventListener('hashchange', () => {
    refreshAuthUI().catch(() => {});
  });

  // Events
  $('eventForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('eventHint');

    if (!confirmWrite('Save this event?')) return;

    hint.textContent = 'Saving…';

    const fd = new FormData(e.currentTarget);
    await api('/api/events', {
      method: 'POST',
      body: JSON.stringify({ title: fd.get('title'), date: fd.get('date'), time: fd.get('time') })
    });

    e.currentTarget.reset();
    hint.textContent = 'Saved.';
    await loadEvents();
  });

  // Bulletins (multipart)
  $('bulletinForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('bulletinHint');

    if (!confirmWrite('Upload and schedule this bulletin?')) return;

    hint.textContent = 'Uploading…';

    const fd = new FormData(e.currentTarget);
    const createAnnouncement = fd.get('createAnnouncement') === 'on';
    fd.set('createAnnouncement', createAnnouncement ? 'true' : 'false');

    const res = await fetch('/api/bulletins/upload', {
      method: 'POST',
      body: fd,
      credentials: 'same-origin'
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      hint.textContent = data.error || 'Upload failed.';
      return;
    }

    hint.textContent = 'Scheduled.';
    e.currentTarget.reset();
    await loadBulletins();
  });

  // Users
  $('userForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('userHint');

    if (!confirmWrite('Create an admin invite link for this email?')) return;

    hint.textContent = 'Creating invite…';

    const fd = new FormData(e.currentTarget);
    const res = await api('/api/users/invite', {
      method: 'POST',
      body: JSON.stringify({ email: String(fd.get('email') || '') })
    });

    e.currentTarget.reset();
    hint.textContent = `Invite link (expires ${new Date(res.expiresAt).toLocaleString()}): ${res.inviteLink}`;
    await loadUsers();
  });

  // Livestream controls
  $('goLiveBtn').addEventListener('click', async () => {
    if (!confirmWrite('Set livestream status to LIVE now?')) return;
    const platform = $('activePlatform').value;
    const platforms = getSelectedLivePlatforms();
    const nextPlatforms = platforms.length ? platforms : [platform];
    if (!nextPlatforms.includes(platform)) nextPlatforms.unshift(platform);
    livestream.active = { platform, platforms: nextPlatforms, status: 'live' };
    await saveLivestream();
  });
  $('goOfflineBtn').addEventListener('click', async () => {
    if (!confirmWrite('Set livestream status to OFFLINE now?')) return;
    const platform = $('activePlatform').value;
    const platforms = getSelectedLivePlatforms();
    const nextPlatforms = platforms.length ? platforms : [platform];
    if (!nextPlatforms.includes(platform)) nextPlatforms.unshift(platform);
    livestream.active = { platform, platforms: nextPlatforms, status: 'offline' };
    await saveLivestream();
  });
  $('saveLivestreamBtn').addEventListener('click', async () => {
    if (!confirmWrite('Save livestream settings?')) return;
    const platform = $('activePlatform').value;
    const platforms = getSelectedLivePlatforms();
    const nextPlatforms = platforms.length ? platforms : [platform];
    if (!nextPlatforms.includes(platform)) nextPlatforms.unshift(platform);
    livestream.active = { platform, platforms: nextPlatforms, status: livestream.active?.status || 'offline' };
    await saveLivestream();
    alert('Saved livestream settings.');
  });

  $('recurringForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!confirmWrite('Add this recurring stream?')) return;

    const fd = new FormData(e.currentTarget);
    const item = {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
      day: String(fd.get('day')),
      time: String(fd.get('time')),
      label: String(fd.get('label'))
    };
    livestream.recurring = [...(livestream.recurring || []), item];
    await saveLivestream();
    e.currentTarget.reset();
  });

  // Social settings
  $('socialForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('socialHint');

    if (!confirmWrite('Save social links?')) return;

    hint.textContent = 'Saving…';
    const fd = new FormData(e.currentTarget);
    await saveSettingsPatch({
      social: {
        facebook: String(fd.get('facebook') || ''),
        youtube: String(fd.get('youtube') || ''),
        email: String(fd.get('email') || ''),
        phone: String(fd.get('phone') || ''),
        address: String(fd.get('address') || '')
      }
    });
    hint.textContent = 'Saved.';
  });

  // Theme settings
  $('themeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hint = $('themeHint');

    if (!confirmWrite('Save theme settings?')) return;

    hint.textContent = 'Saving…';
    const fd = new FormData(e.currentTarget);
    await saveSettingsPatch({
      theme: {
        accent: String(fd.get('accent') || '#c46123'),
        text: String(fd.get('text') || '#ffffff'),
        background: String(fd.get('background') || '#000000')
      }
    });
    hint.textContent = 'Saved (theme.css updated if exports enabled).';
  });

  // Theme: hex input syncing
  const syncHex = (colorInputId, hexInputId) => {
    const colorEl = $(colorInputId);
    const hexEl = $(hexInputId);
    if (!colorEl || !hexEl) return;

    const pushToHex = () => {
      hexEl.value = String(colorEl.value || '').toLowerCase();
      applyThemePreviewCard(getThemeFromInputs());
    };

    const pushToColor = () => {
      const normalized = normalizeHex(hexEl.value);
      if (!normalized) return;
      colorEl.value = normalized;
      applyThemePreviewCard(getThemeFromInputs());
    };

    colorEl.addEventListener('input', pushToHex);
    hexEl.addEventListener('input', () => {
      // live preview only when valid hex
      const normalized = normalizeHex(hexEl.value);
      if (normalized) {
        colorEl.value = normalized;
        applyThemePreviewCard(getThemeFromInputs());
      }
    });
    hexEl.addEventListener('change', pushToColor);

    pushToHex();
  };

  syncHex('themeAccent', 'themeAccentHex');

  // Time pickers
  initTimePicker('recurringTimePicker', 'recurringTime', { required: true, defaultValue: '10:00' });
  initTimePicker('eventTimePicker', 'eventTime', { required: false });
  syncHex('themeText', 'themeTextHex');
  syncHex('themeBackground', 'themeBackgroundHex');

  // Theme: Preview before saving
  const previewBtn = $('previewThemeBtn');
  const clearBtn = $('clearThemePreviewBtn');
  if (previewBtn) {
    previewBtn.addEventListener('click', async () => {
      const hint = $('themeHint');
      hint.textContent = 'Enabling preview…';
      const theme = getThemeFromInputs();
      applyThemePreviewCard(theme);
      await api('/api/theme/preview', { method: 'POST', body: JSON.stringify({ theme }) });
      hint.textContent = 'Preview enabled. A new tab will open with your preview.';
      window.open('/', '_blank');
    });
  }
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      const hint = $('themeHint');
      hint.textContent = 'Clearing preview…';
      await api('/api/theme/preview/clear', { method: 'POST', body: '{}' });
      hint.textContent = 'Preview cleared.';
    });
  }

  $('exportAllBtn').addEventListener('click', async () => {
    if (!confirmWrite('Export current content to website files now?')) return;
    await api('/api/export', { method: 'POST', body: '{}' });
    alert('Exported to website files.');
  });

  // Initial
  refreshAuthUI().catch((err) => {
    $('authStatus').textContent = 'Admin server not running.';
    $('loginError').textContent = err.message;
    $('loginError').hidden = false;
  });
});
