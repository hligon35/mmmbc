let csrfToken = '';
let csrfReady = Promise.resolve();

async function fetchCsrfToken() {
  try {
    const res = await fetch('/api/csrf', { method: 'GET', credentials: 'same-origin' });
    if (!res.ok) return '';
    const data = await res.json();
    csrfToken = String(data?.csrfToken || '');
    return csrfToken;
  } catch {
    return '';
  }
}

async function api(path, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const needsCsrf = path.startsWith('/api/')
    && !['GET', 'HEAD', 'OPTIONS'].includes(method)
    && !path.startsWith('/api/auth/login')
    && !path.startsWith('/api/auth/logout')
    && !path.startsWith('/api/auth/recover')
    && !path.startsWith('/api/invites/');

  if (needsCsrf) {
    await csrfReady;
  }

  const headers = {
    ...(options.headers || {}),
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' })
  };
  if (needsCsrf && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  const res = await fetch(path, {
    headers,
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

function isWorkersDeployment() {
  // Option B runs on Cloudflare Workers, usually on a *.workers.dev hostname.
  // In that mode, authentication is handled by Cloudflare Access instead of the legacy password form.
  const host = String(window.location.hostname || '').toLowerCase();
  return host.endsWith('.workers.dev');
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
  const minuteRaw = String(minute || '').trim();
  if (minuteRaw === '') return '';
  const minuteNum = Number(minuteRaw);
  if (!Number.isFinite(minuteNum) || minuteNum < 0 || minuteNum > 59) return '';
  const m = String(Math.floor(minuteNum)).padStart(2, '0');
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

  const makeDatalist = (id, values) => {
    const dl = document.createElement('datalist');
    dl.id = id;
    for (const v of values) {
      const opt = document.createElement('option');
      opt.value = String(v);
      dl.appendChild(opt);
    }
    return dl;
  };

  const hour = document.createElement('input');
  hour.className = 'select';
  hour.setAttribute('aria-label', 'H');
  hour.setAttribute('inputmode', 'numeric');
  hour.setAttribute('autocomplete', 'off');
  hour.placeholder = required ? 'H' : 'Hour';

  const minute = document.createElement('input');
  minute.className = 'select';
  minute.setAttribute('aria-label', 'M');
  minute.setAttribute('inputmode', 'numeric');
  minute.setAttribute('autocomplete', 'off');
  minute.placeholder = required ? 'M' : 'Min';

  const ampm = document.createElement('input');
  ampm.className = 'select';
  ampm.setAttribute('aria-label', 'A/P');
  ampm.setAttribute('autocomplete', 'off');
  ampm.placeholder = required ? 'AM/PM' : 'AM/PM';

  const hoursListId = `${pickerId}__hours`;
  const minutesListId = `${pickerId}__minutes`;
  const ampmListId = `${pickerId}__ampm`;

  hour.setAttribute('list', hoursListId);
  minute.setAttribute('list', minutesListId);
  ampm.setAttribute('list', ampmListId);

  const hours = [];
  for (let h = 1; h <= 12; h += 1) hours.push(String(h));
  const minutes = [];
  for (let m = 0; m <= 59; m += 1) minutes.push(String(m).padStart(2, '0'));
  const ampmVals = ['AM', 'PM'];

  root.appendChild(hour);
  root.appendChild(minute);
  root.appendChild(ampm);
  root.appendChild(makeDatalist(hoursListId, hours));
  root.appendChild(makeDatalist(minutesListId, minutes));
  root.appendChild(makeDatalist(ampmListId, ampmVals));

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

  hour.addEventListener('input', syncToHidden);
  minute.addEventListener('input', syncToHidden);
  ampm.addEventListener('input', syncToHidden);
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
    $('tabBtn-finances'),
    $('tabBtn-settings'),
    $('tabBtn-account')
  ];
  const panels = [
    $('tab-photos'),
    $('tab-stream'),
    $('tab-events'),
    $('tab-content'),
    $('tab-finances'),
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

  const financeTopBar = $('financeTopBar');
  if (financeTopBar) financeTopBar.hidden = activeId !== 'tab-finances';
}

async function refreshAuthUI() {
  let me = { user: null };
  try {
    me = await api('/api/me', { method: 'GET' });
  } catch {
    me = { user: null };
  }
  const loggedIn = !!me.user;

  const inviteToken = getInviteTokenFromHash();
  const inInviteFlow = !!inviteToken;

  $('inviteCard').hidden = !inInviteFlow;
  $('loginCard').hidden = loggedIn || inInviteFlow;
  $('dashboardCard').hidden = !loggedIn || inInviteFlow;
  $('logoutBtn').hidden = !loggedIn;
  $('accountBtn').hidden = !loggedIn;

  // Option B (Workers): use a custom login page that triggers Cloudflare Access.
  // The legacy password form is not used in Workers deployments.
  if (!loggedIn && !inInviteFlow && isWorkersDeployment()) {
    const here = String(window.location.pathname || '');
    if (!here.endsWith('/admin/login.html')) {
      window.location.replace('/admin/login.html');
      return;
    }
  }

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
    csrfReady = fetchCsrfToken();
    await csrfReady;
    await loadAll();
    applyHashNavigation();
  }

  if (inInviteFlow) {
    await loadInvite(inviteToken);
  }
}

async function login(email, password, twoFactorCode) {
  if (isWorkersDeployment()) {
    // In Option B, Access is the auth layer (no password login endpoint).
    throw new Error('This admin uses Cloudflare Access. Use Access login, then refresh.');
  }
  const code = String(twoFactorCode || '').trim();
  await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email,
      password,
      ...(code ? { twoFactorCode: code } : {})
    })
  });

  csrfReady = fetchCsrfToken();
  await csrfReady;
}

async function logout() {
  await api('/api/auth/logout', { method: 'POST', body: '{}' });
  csrfToken = '';
  csrfReady = Promise.resolve();
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
  if (h === 'finances' || h === 'finance') setTab('tab-finances');
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

// -------- Finances --------
let finances = { entries: [], meta: { categories: [], funds: [] } };
let financeQuickKind = 'income';
let financeGivingPeriod = 'week';

function formatMoneyCents(cents) {
  const n = Number(cents || 0) / 100;
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);
}

function setFinanceHint(text) {
  const el = $('financeHint');
  if (!el) return;
  el.textContent = String(text || '');
}

function financeSelectedTypes() {
  const incomeEl = $('financeTypeIncome');
  const expenseEl = $('financeTypeExpense');

  // Backward compatible: fall back to the legacy single-select if the new checkboxes aren't present.
  if (!incomeEl && !expenseEl) {
    const legacy = $('financeTypeFilter');
    const t = String(legacy?.value || '').trim();
    return t ? [t] : [];
  }

  const types = [];
  if (incomeEl?.checked) types.push('income');
  if (expenseEl?.checked) types.push('expense');

  // If none or both are selected, treat it as "All".
  if (types.length === 0 || types.length === 2) return [];
  return types;
}

function financeNormalizeKey(value) {
  return String(value || '').trim().toLowerCase();
}

function financeDetectKindFromEntry(entry) {
  const t = String(entry?.type || '');
  if (t === 'expense') return 'expense';
  if (t === 'income') {
    const cat = financeNormalizeKey(entry?.category);
    if (cat.includes('tithe')) return 'tithes';
    if (cat.includes('offering')) return 'offerings';
    return 'income';
  }
  return 'income';
}

function financeApplyKindToForm(kind) {
  const typeEl = $('financeType');
  const catEl = $('financeCategory');
  const isEditing = !!String($('financeEditId')?.value || '').trim();

  if (typeEl) {
    typeEl.disabled = true;
    typeEl.value = (kind === 'expense') ? 'expense' : 'income';
  }

  if (catEl) {
    if (kind === 'tithes') {
      if (!isEditing) catEl.value = 'Tithes';
      catEl.disabled = true;
    } else if (kind === 'offerings') {
      if (!isEditing) catEl.value = 'Offerings';
      catEl.disabled = true;
    } else {
      catEl.disabled = false;
      if (!isEditing) {
        // Only clear on add-mode; keep category when editing.
        if (kind === 'income' && !String(catEl.value || '').trim()) catEl.value = '';
        if (kind === 'expense' && !String(catEl.value || '').trim()) catEl.value = '';
      }
    }
  }

  const partyLabel = $('financePartyLabel');
  const partyInput = $('financeParty');
  if (partyLabel) {
    if (kind === 'expense') partyLabel.textContent = 'To (optional)';
    else if (kind === 'tithes') partyLabel.textContent = 'Giver (required)';
    else if (kind === 'offerings') partyLabel.textContent = 'Giver (optional)';
    else partyLabel.textContent = 'From (optional)';
  }
  if (partyInput instanceof HTMLInputElement) {
    partyInput.required = (kind === 'tithes');
  }
}

function financeSetQuickKind(kind, { render = true } = {}) {
  const k = String(kind || '').trim();
  if (!k) return;
  financeQuickKind = k;

  // Sync the mini-tabs UI
  const tabs = $('financeQuickTabs');
  if (tabs) {
    const btns = Array.from(tabs.querySelectorAll('[data-fin-kind]'));
    for (const b of btns) {
      const v = String(b.getAttribute('data-fin-kind') || '');
      b.setAttribute('aria-selected', v === financeQuickKind ? 'true' : 'false');
    }
  }

  // Sync the type checkboxes in the filter menu.
  const incomeCb = $('financeTypeIncome');
  const expenseCb = $('financeTypeExpense');
  if (incomeCb instanceof HTMLInputElement && expenseCb instanceof HTMLInputElement) {
    if (financeQuickKind === 'expense') {
      incomeCb.checked = false;
      expenseCb.checked = true;
    } else {
      incomeCb.checked = true;
      expenseCb.checked = false;
    }
  }

  financeApplyKindToForm(financeQuickKind);
  if (render) renderFinances();
}

function financeReadCheckedRangeDays(menuEl) {
  if (!menuEl) return [];
  const inputs = Array.from(menuEl.querySelectorAll('input[data-fin-range]'));
  const days = [];
  for (const el of inputs) {
    if (!(el instanceof HTMLInputElement)) continue;
    if (!el.checked) continue;
    const v = String(el.getAttribute('data-fin-range') || '').trim();
    if (/^\d+$/.test(v)) days.push(Number(v));
  }
  return days;
}

function financeCurrentFilters() {
  const selectedTypes = financeSelectedTypes();
  return {
    from: String($('financeFrom')?.value || ''),
    to: String($('financeTo')?.value || ''),
    type: String($('financeTypeFilter')?.value || ''),
    types: selectedTypes,
    kind: String(financeQuickKind || ''),
    search: String($('financeSearch')?.value || '').trim().toLowerCase()
  };
}

function setFinanceRangePreset(days) {
  const fromEl = $('financeFrom');
  const toEl = $('financeTo');
  if (!fromEl || !toEl) return;

  const d = Number(days);
  if (!Number.isFinite(d) || d <= 0) return;

  const to = isoDateToday();
  const from = addDaysToIsoDate(to, -(d - 1));
  fromEl.value = from;
  toEl.value = to;
}

function setFinanceCustomMode(enabled) {
  const panel = $('financeCustomRange');
  if (!panel) return;
  panel.hidden = !enabled;
}

function financeEntryMatches(entry, filters) {
  const date = String(entry?.date || '');
  if (filters.from && date && date < filters.from) return false;
  if (filters.to && date && date > filters.to) return false;

  const entryType = String(entry?.type || '');
  if (Array.isArray(filters.types) && filters.types.length > 0) {
    if (!filters.types.includes(entryType)) return false;
  } else if (filters.type && entryType !== filters.type) {
    // Legacy single-select support
    return false;
  }

  const kind = String(filters?.kind || '').trim();
  if (kind === 'income' && entryType !== 'income') return false;
  if (kind === 'expense' && entryType !== 'expense') return false;
  if (kind === 'tithes') {
    if (entryType !== 'income') return false;
    if (!financeNormalizeKey(entry?.category).includes('tithe')) return false;
  }
  if (kind === 'offerings') {
    if (entryType !== 'income') return false;
    if (!financeNormalizeKey(entry?.category).includes('offering')) return false;
  }

  if (filters.search) {
    const hay = [
      entry?.category,
      entry?.fund,
      entry?.method,
      entry?.party,
      entry?.memo,
      entry?.type,
      entry?.date
    ].map((v) => String(v || '').toLowerCase()).join(' ');
    if (!hay.includes(filters.search)) return false;
  }
  return true;
}

function populateFinanceDatalists() {
  const catList = $('financeCategoriesList');
  const fundList = $('financeFundsList');
  if (catList) {
    catList.innerHTML = '';
    for (const c of (finances?.meta?.categories || [])) {
      const opt = document.createElement('option');
      opt.value = String(c || '');
      catList.appendChild(opt);
    }
  }
  if (fundList) {
    fundList.innerHTML = '';
    for (const f of (finances?.meta?.funds || [])) {
      const opt = document.createElement('option');
      opt.value = String(f || '');
      fundList.appendChild(opt);
    }
  }
}

function financeSetEditMode(isEditing) {
  const cancelBtn = $('financeCancelEditBtn');
  const saveBtn = $('financeSaveBtn');
  if (cancelBtn) cancelBtn.hidden = !isEditing;
  if (saveBtn) saveBtn.textContent = isEditing ? 'Save Changes' : 'Add Entry';
}

function financeResetForm() {
  $('financeEditId').value = '';
  $('financeType').value = 'income';
  $('financeCategory').value = '';
  $('financeFund').value = '';
  $('financeMethod').value = '';
  $('financeAmount').value = '';
  $('financeParty').value = '';
  $('financeMemo').value = '';

  // Default date to today if empty.
  if (!$('financeDate').value) {
    $('financeDate').value = new Date().toISOString().slice(0, 10);
  }

  financeSetEditMode(false);

  // Ensure the form reflects the selected quick tab.
  financeApplyKindToForm(financeQuickKind);
}

function financeStartEdit(entry) {
  if (!entry) return;
  financeSetQuickKind(financeDetectKindFromEntry(entry), { render: false });
  $('financeEditId').value = String(entry.id || '');
  $('financeDate').value = String(entry.date || '');
  $('financeType').value = String(entry.type || 'income');
  $('financeCategory').value = String(entry.category || '');
  $('financeFund').value = String(entry.fund || '');
  $('financeMethod').value = String(entry.method || '');
  $('financeAmount').value = (Number(entry.amountCents || 0) / 100).toFixed(2);
  $('financeParty').value = String(entry.party || '');
  $('financeMemo').value = String(entry.memo || '');
  financeSetEditMode(true);
  try { $('financeCategory').focus(); } catch { /* ignore */ }
}

function renderFinances() {
  populateFinanceDatalists();

  const filters = financeCurrentFilters();
  const all = Array.isArray(finances?.entries) ? finances.entries : [];
  const rows = all.filter((e) => financeEntryMatches(e, filters));

  let income = 0;
  let expense = 0;
  for (const e of rows) {
    const cents = Number(e?.amountCents || 0);
    if (String(e?.type) === 'income') income += cents;
    if (String(e?.type) === 'expense') expense += cents;
  }
  const net = income - expense;

  if ($('financeIncomeTotal')) $('financeIncomeTotal').textContent = `${formatMoneyCents(income)} income`;
  if ($('financeExpenseTotal')) $('financeExpenseTotal').textContent = `${formatMoneyCents(expense)} expense`;
  if ($('financeNetTotal')) $('financeNetTotal').textContent = `${formatMoneyCents(net)} net`;

  const meta = $('financePrintMeta');
  if (meta) {
    const range = filters.from || filters.to ? `${filters.from || '…'} to ${filters.to || '…'}` : 'All dates';
    meta.textContent = `${range} • ${rows.length} entries • Income ${formatMoneyCents(income)} • Expense ${formatMoneyCents(expense)} • Net ${formatMoneyCents(net)}`;
  }

  const tbody = $('financeTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  // Weekly Giving summary is independent of the table/filters.
  renderWeeklyGiving();

  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 9;
    td.textContent = 'No entries match the current filters.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const e of rows) {
    const tr = document.createElement('tr');

    const amountCents = Number(e?.amountCents || 0);
    const amtTd = document.createElement('td');
    amtTd.className = `num ${String(e?.type) === 'income' ? 'financeAmt--income' : 'financeAmt--expense'}`;
    const sign = String(e?.type) === 'expense' ? '-' : '';
    amtTd.textContent = `${sign}${formatMoneyCents(amountCents)}`;

    const mkTd = (text) => {
      const td = document.createElement('td');
      td.textContent = String(text || '');
      return td;
    };

    tr.appendChild(mkTd(e?.date));
    tr.appendChild(mkTd(e?.type));
    tr.appendChild(mkTd(e?.category));
    tr.appendChild(mkTd(e?.fund));
    tr.appendChild(mkTd(e?.method));
    tr.appendChild(mkTd(e?.party));
    tr.appendChild(mkTd(e?.memo));
    tr.appendChild(amtTd);

    const actions = document.createElement('td');
    actions.className = 'noPrint';

    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'btn btn--sm';
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', () => financeStartEdit(e));

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn--sm';
    delBtn.textContent = 'Delete';
    delBtn.addEventListener('click', async () => {
      if (!confirmWrite('Delete this finance entry? This cannot be undone.')) return;
      setFinanceHint('Deleting…');
      try {
        const res = await api(`/api/finances/entries/${encodeURIComponent(String(e.id))}`, { method: 'DELETE' });
        finances = res.data;
        financeResetForm();
        renderFinances();
        setFinanceHint('Deleted.');
      } catch (err) {
        setFinanceHint(err.message);
      }
    });

    actions.appendChild(editBtn);
    actions.appendChild(delBtn);
    actions.style.display = 'flex';
    actions.style.gap = '8px';

    tr.appendChild(actions);
    tbody.appendChild(tr);
  }

  renderWeeklyGiving();
}

async function loadFinances() {
  const data = await api('/api/finances', { method: 'GET' });
  finances = data;
  if ($('financeDate') && !$('financeDate').value) $('financeDate').value = isoDateToday();
  // Hide custom range UI unless the user explicitly opens it.
  if ($('financeCustomRange')) {
    const customToggle = $('financeCustomToggle');
    const wantsCustom = (customToggle instanceof HTMLInputElement) ? !!customToggle.checked : false;
    setFinanceCustomMode(wantsCustom);
  }
  renderFinances();
}

function financeCsvEscape(value) {
  const s = String(value ?? '');
  if (/[\n\r,\"]/g.test(s)) return `"${s.replace(/\"/g, '""')}"`;
  return s;
}

function downloadTextFile(name, text, mime) {
  const blob = new Blob([text], { type: mime || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function isoDateToday() {
  return new Date().toISOString().slice(0, 10);
}

function addDaysToIsoDate(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00`);
  d.setDate(d.getDate() + Number(days || 0));
  return d.toISOString().slice(0, 10);
}

function startOfMonth(isoDate) {
  const d = new Date(`${isoDate}T00:00:00`);
  d.setDate(1);
  return d.toISOString().slice(0, 10);
}

function startOfWeekSunday(isoDate) {
  const d = new Date(`${isoDate}T00:00:00`);
  const day = d.getDay(); // 0=Sun
  d.setDate(d.getDate() - day);
  return d.toISOString().slice(0, 10);
}

function normalizeCategoryKey(value) {
  return String(value || '').trim().toLowerCase();
}

function renderWeeklyGiving() {
  const today = isoDateToday();
  let from = '';
  let to = '';

  if (financeGivingPeriod === 'month') {
    from = startOfMonth(today);
    to = today;
  } else {
    from = startOfWeekSunday(today);
    to = addDaysToIsoDate(from, 6);
  }

  const tithesKey = 'tithes';
  const offeringsKey = 'offerings';

  const entries = Array.isArray(finances?.entries) ? finances.entries : [];
  const inRange = entries.filter((e) => {
    const d = String(e?.date || '');
    if (!d) return false;
    if (from && d < from) return false;
    if (to && d > to) return false;
    return true;
  });

  let tithes = 0;
  let offerings = 0;

  for (const e of inRange) {
    if (String(e?.type) !== 'income') continue;
    const cat = normalizeCategoryKey(e?.category);
    const cents = Number(e?.amountCents || 0);
    if (!Number.isFinite(cents)) continue;
    if (cat === tithesKey || (tithesKey === 'tithes' && cat.includes('tithe'))) tithes += cents;
    if (cat === offeringsKey || (offeringsKey === 'offerings' && cat.includes('offering'))) offerings += cents;
  }

  const total = tithes + offerings;
  if ($('financeTithesTotal')) $('financeTithesTotal').textContent = `${formatMoneyCents(tithes)} tithes`;
  if ($('financeOfferingsTotal')) $('financeOfferingsTotal').textContent = `${formatMoneyCents(offerings)} offerings`;
  if ($('financeGivingTotal')) $('financeGivingTotal').textContent = `${formatMoneyCents(total)} total`;
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
let photoArrangeAlbum = '';

function toNumberOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function buildAlbumList(items) {
  const albums = Array.from(new Set((items || []).map((i) => String(i.album || '').trim()).filter(Boolean)));
  albums.sort((a, b) => a.localeCompare(b));
  return albums;
}

function renderArrangeAlbumOptions() {
  const select = $('photoArrangeAlbum');
  if (!select) return;
  const albums = buildAlbumList(galleryItems);
  const current = String(photoArrangeAlbum || '');

  select.innerHTML = '<option value="">(Pick an album)</option>';
  for (const a of albums) {
    const opt = document.createElement('option');
    opt.value = a;
    opt.textContent = a;
    select.appendChild(opt);
  }
  if (albums.includes(current)) select.value = current;
}

function isManualMode() {
  return $('photoSort')?.value === 'manual' && String(photoArrangeAlbum || '').trim();
}

function applyPhotoFilters() {
  const sort = $('photoSort').value;
  const albumFilter = $('photoAlbumFilter').value.trim().toLowerCase();
  const tagFilter = $('photoTagFilter').value.trim().toLowerCase();

  let items = [...galleryItems];
  if (albumFilter) items = items.filter((i) => String(i.album || '').toLowerCase().includes(albumFilter));
  if (tagFilter) items = items.filter((i) => (i.tags || []).some((t) => String(t).toLowerCase().includes(tagFilter)));

  const manualAlbum = String(photoArrangeAlbum || '').trim();
  if (sort === 'manual' && manualAlbum) {
    items = items.filter((i) => String(i.album || '') === manualAlbum);
    items.sort((a, b) => {
      const ap = toNumberOrNull(a.position);
      const bp = toNumberOrNull(b.position);
      if (ap === null && bp === null) return String(b.createdAt).localeCompare(String(a.createdAt));
      if (ap === null) return 1;
      if (bp === null) return -1;
      if (ap !== bp) return ap - bp;
      return String(b.createdAt).localeCompare(String(a.createdAt));
    });
  } else {
    items.sort((a, b) => {
      if (sort === 'name-asc') return String(a.originalName).localeCompare(String(b.originalName));
      if (sort === 'name-desc') return String(b.originalName).localeCompare(String(a.originalName));
      if (sort === 'date-asc') return String(a.createdAt).localeCompare(String(b.createdAt));
      return String(b.createdAt).localeCompare(String(a.createdAt));
    });
  }

  renderPhotoGrid(items);
}

async function saveManualOrder(album, orderedIds) {
  await api('/api/gallery/order', {
    method: 'PUT',
    body: JSON.stringify({ album, orderedIds })
  });

  // Update local positions so the UI stays in sync without a full reload.
  const byId = new Map(galleryItems.map((it) => [String(it.id), it]));
  orderedIds.forEach((id, idx) => {
    const it = byId.get(String(id));
    if (it) it.position = idx;
  });
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

    if (isManualMode()) {
      const up = document.createElement('button');
      up.className = 'btn';
      up.type = 'button';
      up.textContent = 'Up';

      const down = document.createElement('button');
      down.className = 'btn';
      down.type = 'button';
      down.textContent = 'Down';

      up.addEventListener('click', async () => {
        const album = String(photoArrangeAlbum || '').trim();
        if (!album) return;
        const ordered = items.map((x) => String(x.id));
        const idx = ordered.indexOf(String(item.id));
        if (idx <= 0) return;
        [ordered[idx - 1], ordered[idx]] = [ordered[idx], ordered[idx - 1]];
        await saveManualOrder(album, ordered);
        applyPhotoFilters();
      });

      down.addEventListener('click', async () => {
        const album = String(photoArrangeAlbum || '').trim();
        if (!album) return;
        const ordered = items.map((x) => String(x.id));
        const idx = ordered.indexOf(String(item.id));
        if (idx === -1 || idx >= ordered.length - 1) return;
        [ordered[idx + 1], ordered[idx]] = [ordered[idx], ordered[idx + 1]];
        await saveManualOrder(album, ordered);
        applyPhotoFilters();
      });

      actions.appendChild(up);
      actions.appendChild(down);
    }

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
  renderArrangeAlbumOptions();
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
    loadFinances(),
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
  $('tabBtn-finances').addEventListener('click', () => setTab('tab-finances'));
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

  // Finances
  if ($('financeEntryForm')) {
    const forceDatePickerOpen = (inputId) => {
      const input = $(inputId);
      if (!(input instanceof HTMLInputElement)) return;
      if (String(input.type || '') !== 'date') return;
      const open = () => {
        try { input.focus(); } catch { /* ignore */ }
        const sp = input.showPicker;
        if (typeof sp === 'function') {
          try { sp.call(input); } catch { /* ignore */ }
        }
      };

      // Clicking the label/container should also open the picker.
      const label = input.closest('label');
      if (label) {
        label.addEventListener('click', (e) => {
          if (e.target === input) return;
          open();
        });
      }

      // Clicking in the input should open it too (consistent behavior).
      input.addEventListener('click', () => open());
    };

    forceDatePickerOpen('financeDate');
    forceDatePickerOpen('financeFrom');
    forceDatePickerOpen('financeTo');

    $('financeEntryForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      setFinanceHint('');

      const id = String($('financeEditId').value || '');
      const payload = {
        date: String($('financeDate').value || ''),
        type: String($('financeType').value || ''),
        category: String($('financeCategory').value || ''),
        fund: String($('financeFund').value || ''),
        method: String($('financeMethod').value || ''),
        amount: String($('financeAmount').value || ''),
        party: String($('financeParty').value || ''),
        memo: String($('financeMemo').value || '')
      };

      if (!confirmWrite(id ? 'Save changes to this entry?' : 'Add this finance entry?')) return;
      setFinanceHint(id ? 'Saving…' : 'Adding…');

      try {
        const res = await api(id
          ? `/api/finances/entries/${encodeURIComponent(id)}`
          : '/api/finances/entries',
        {
          method: id ? 'PUT' : 'POST',
          body: JSON.stringify(payload)
        });
        finances = res.data;
        financeResetForm();
        renderFinances();
        setFinanceHint(id ? 'Saved.' : 'Added.');
      } catch (err) {
        setFinanceHint(err.message);
      }
    });
  }

  if ($('financeCancelEditBtn')) {
    $('financeCancelEditBtn').addEventListener('click', () => {
      financeResetForm();
      renderFinances();
      setFinanceHint('');
    });
  }

  for (const id of ['financeFrom', 'financeTo', 'financeSearch']) {
    const el = $(id);
    if (!el) continue;
    el.addEventListener('input', () => renderFinances());
    el.addEventListener('change', () => renderFinances());
  }

  for (const id of ['financeTypeIncome', 'financeTypeExpense']) {
    const el = $(id);
    if (!el) continue;
    el.addEventListener('change', () => renderFinances());
  }

  // Finance quick tabs (Income / Expense / Tithes / Offerings)
  if ($('financeQuickTabs')) {
    const wrap = $('financeQuickTabs');
    const btns = Array.from(wrap.querySelectorAll('[data-fin-kind]'));
    for (const b of btns) {
      b.addEventListener('click', () => {
        const kind = b.getAttribute('data-fin-kind');
        financeSetQuickKind(kind);
      });
    }
  }

  const setGivingPeriod = (period) => {
    financeGivingPeriod = (period === 'month') ? 'month' : 'week';
    const wk = $('financePeriodWeekBtn');
    const mon = $('financePeriodMonthBtn');
    if (wk) wk.setAttribute('aria-selected', financeGivingPeriod === 'week' ? 'true' : 'false');
    if (mon) mon.setAttribute('aria-selected', financeGivingPeriod === 'month' ? 'true' : 'false');
    renderWeeklyGiving();
  };

  if ($('financePeriodWeekBtn')) {
    $('financePeriodWeekBtn').addEventListener('click', () => setGivingPeriod('week'));
  }
  if ($('financePeriodMonthBtn')) {
    $('financePeriodMonthBtn').addEventListener('click', () => setGivingPeriod('month'));
  }

  // Default to current week in the giving chips.
  setGivingPeriod(financeGivingPeriod);

  // Default quick view
  financeSetQuickKind(financeQuickKind, { render: false });

  if ($('financeSearchForm')) {
    $('financeSearchForm').addEventListener('submit', (e) => {
      e.preventDefault();
      renderFinances();
      const menu = $('financeFilterMenu');
      if (menu && menu.open) menu.open = false;
    });
  }

  // Filter dropdown (multi-select presets + custom)
  if ($('financeFilterMenu')) {
    const menu = $('financeFilterMenu');
    const rangeInputs = Array.from(menu.querySelectorAll('input[data-fin-range]'))
      .filter((el) => el instanceof HTMLInputElement);
    const customToggle = $('financeCustomToggle');

    const uncheckNumericRanges = () => {
      for (const el of rangeInputs) {
        const v = String(el.getAttribute('data-fin-range') || '').trim();
        if (/^\d+$/.test(v)) el.checked = false;
      }
    };

    const applyCheckedPresets = () => {
      const days = financeReadCheckedRangeDays(menu);
      if (days.length > 0) {
        setFinanceCustomMode(false);
        if (customToggle instanceof HTMLInputElement) customToggle.checked = false;
        setFinanceRangePreset(Math.max(...days));
        return true;
      }
      return false;
    };

    for (const el of rangeInputs) {
      el.addEventListener('change', () => {
        const v = String(el.getAttribute('data-fin-range') || '').trim();

        if (v === 'custom') {
          const isOn = !!el.checked;
          setFinanceCustomMode(isOn);
          if (isOn) uncheckNumericRanges();
          renderFinances();
          return;
        }

        // Numeric preset changed
        setFinanceCustomMode(false);
        if (customToggle instanceof HTMLInputElement) customToggle.checked = false;

        const applied = applyCheckedPresets();
        if (!applied) {
          if ($('financeFrom')) $('financeFrom').value = '';
          if ($('financeTo')) $('financeTo').value = '';
        }
        renderFinances();
      });
    }
  }

  if ($('financeApplyCustomRangeBtn')) {
    $('financeApplyCustomRangeBtn').addEventListener('click', () => {
      setFinanceCustomMode(true);
      if ($('financeCustomToggle') instanceof HTMLInputElement) $('financeCustomToggle').checked = true;
      renderFinances();
      const menu = $('financeFilterMenu');
      if (menu) menu.open = false;
    });
  }

  if ($('financeClearRangeBtn')) {
    $('financeClearRangeBtn').addEventListener('click', () => {
      if ($('financeFrom')) $('financeFrom').value = '';
      if ($('financeTo')) $('financeTo').value = '';
      if ($('financeCustomToggle') instanceof HTMLInputElement) $('financeCustomToggle').checked = false;
      if ($('financeFilterMenu')) {
        const menu = $('financeFilterMenu');
        const rangeInputs = Array.from(menu.querySelectorAll('input[data-fin-range]'))
          .filter((el) => el instanceof HTMLInputElement);
        for (const el of rangeInputs) {
          const v = String(el.getAttribute('data-fin-range') || '').trim();
          if (/^\d+$/.test(v)) el.checked = false;
        }
      }
      setFinanceCustomMode(false);
      renderFinances();
      const menu = $('financeFilterMenu');
      if (menu) menu.open = false;
    });
  }

  if ($('financeExportCsvBtn')) {
    $('financeExportCsvBtn').addEventListener('click', () => {
      const filters = financeCurrentFilters();
      const rows = (finances?.entries || []).filter((en) => financeEntryMatches(en, filters));
      const header = ['Date', 'Type', 'Category', 'Fund', 'Method', 'FromTo', 'Memo', 'Amount'];
      const lines = [header.map(financeCsvEscape).join(',')];
      for (const r of rows) {
        const amount = (Number(r.amountCents || 0) / 100).toFixed(2);
        lines.push([
          r.date,
          r.type,
          r.category,
          r.fund,
          r.method,
          r.party,
          r.memo,
          amount
        ].map(financeCsvEscape).join(','));
      }
      const stamp = new Date().toISOString().slice(0, 10);
      downloadTextFile(`finances_${stamp}.csv`, lines.join('\n'), 'text/csv');
    });
  }

  if ($('financePrintBtn')) {
    $('financePrintBtn').addEventListener('click', () => {
      window.print();
    });
  }

  // Password peek + meters
  wirePeekButtons();
  wirePasswordMeter('recoverNewPassword', 'recoverPwMeter', 'recoverPwText');
  wirePasswordMeter('newPassword', 'accountPwMeter', 'accountPwText');
  // Optional: user creation temp password uses policy checks; meter not shown in UI.

  // Login
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('loginError').hidden = true;

    if (isWorkersDeployment()) {
      // Prefer the explicit Access link if present.
      const link = $('accessLoginBtn');
      const href = String(link?.getAttribute('href') || '/cdn-cgi/access/login');
      window.location.href = href;
      return;
    }

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
    await csrfReady;
    const res = await fetch('/api/gallery/upload', {
      method: 'POST',
      body: fd,
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
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

  $('photoArrangeAlbum').addEventListener('change', (e) => {
    photoArrangeAlbum = String(e.currentTarget.value || '').trim();
    // If they picked an album, default to manual ordering.
    if (photoArrangeAlbum) {
      const sortSel = $('photoSort');
      if (sortSel) sortSel.value = 'manual';
    }
    applyPhotoFilters();
  });

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

    await csrfReady;
    const res = await fetch('/api/bulletins/upload', {
      method: 'POST',
      body: fd,
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
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
