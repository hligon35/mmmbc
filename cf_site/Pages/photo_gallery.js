(function () {
  'use strict';

  const pageSize = 24;

  const photoGrid = document.getElementById('photoGrid');
  const prevPage = document.getElementById('prevPage');
  const nextPage = document.getElementById('nextPage');
  const pageInfo = document.getElementById('pageInfo');

  const albumFilter = document.getElementById('albumFilter');
  const sortBy = document.getElementById('sortBy');
  const tagSearch = document.getElementById('tagSearch');

  const overlay = document.getElementById('lightboxOverlay');
  const lbImage = document.getElementById('lightboxImage');
  const lbCaption = document.getElementById('lightboxCaption');
  const lbClose = document.getElementById('lightboxClose');
  const lbPrev = document.getElementById('lightboxPrev');
  const lbNext = document.getElementById('lightboxNext');

  let allItems = [];
  let filtered = [];
  let currentPage = 1;
  let lightboxIndex = -1;

  function safeText(input) {
    return String(input || '').trim();
  }

  function normalizeItems(items) {
    return (items || []).map((it) => ({
      id: it.id || '',
      album: safeText(it.album || 'General'),
      label: safeText(it.label || ''),
      tags: Array.isArray(it.tags) ? it.tags.map((t) => safeText(t).toLowerCase()).filter(Boolean) : [],
      file: safeText(it.file || ''),
      thumb: safeText(it.thumb || it.file || ''),
      originalName: safeText(it.originalName || ''),
      createdAt: safeText(it.createdAt || ''),
      position: Number.isFinite(Number(it.position)) ? Number(it.position) : null
    }));
  }

  function buildAlbumOptions(items) {
    const albums = Array.from(new Set(items.map((i) => i.album).filter(Boolean))).sort((a, b) => a.localeCompare(b));
    const current = albumFilter.value;

    albumFilter.innerHTML = '<option value="">All</option>';
    for (const album of albums) {
      const opt = document.createElement('option');
      opt.value = album;
      opt.textContent = album;
      albumFilter.appendChild(opt);
    }

    if (albums.includes(current)) albumFilter.value = current;
  }

  function applyFilters() {
    const album = safeText(albumFilter.value);
    const tagsQuery = safeText(tagSearch.value).toLowerCase();

    filtered = [...allItems];

    if (album) {
      filtered = filtered.filter((i) => i.album === album);
    }

    if (tagsQuery) {
      filtered = filtered.filter((i) => i.tags.some((t) => t.includes(tagsQuery)));
    }

    const sort = sortBy.value;
    filtered.sort((a, b) => {
      if (sort === 'manual') {
        const ap = a.position;
        const bp = b.position;
        if (ap === null && bp === null) return b.createdAt.localeCompare(a.createdAt);
        if (ap === null) return 1;
        if (bp === null) return -1;
        if (ap !== bp) return ap - bp;
        return b.createdAt.localeCompare(a.createdAt);
      }
      if (sort === 'name-asc') return a.originalName.localeCompare(b.originalName);
      if (sort === 'name-desc') return b.originalName.localeCompare(a.originalName);
      if (sort === 'date-asc') return a.createdAt.localeCompare(b.createdAt);
      return b.createdAt.localeCompare(a.createdAt);
    });

    currentPage = 1;
    render();
  }

  function setPagination(totalCount) {
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
    currentPage = Math.min(currentPage, totalPages);

    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    prevPage.disabled = currentPage <= 1;
    nextPage.disabled = currentPage >= totalPages;
  }

  function openLightbox(indexInFiltered) {
    lightboxIndex = indexInFiltered;
    const item = filtered[lightboxIndex];
    if (!item) return;

    lbImage.src = item.file;
    lbImage.alt = item.label || 'Gallery image';

    const label = item.label || item.album || 'Photo';
    const number = `${lightboxIndex + 1} of ${filtered.length}`;
    lbCaption.textContent = `${label} • ${number}`;

    overlay.classList.add('visible');
    overlay.setAttribute('aria-hidden', 'false');
  }

  function closeLightbox() {
    overlay.classList.remove('visible');
    overlay.setAttribute('aria-hidden', 'true');
    lbImage.src = '';
    lightboxIndex = -1;
  }

  function stepLightbox(delta) {
    if (lightboxIndex === -1) return;
    const next = lightboxIndex + delta;
    if (next < 0 || next >= filtered.length) return;
    openLightbox(next);
  }

  function render() {
    const total = filtered.length;
    setPagination(total);

    photoGrid.innerHTML = '';

    if (!total) {
      const empty = document.createElement('div');
      empty.style.color = '#fff';
      empty.style.textAlign = 'center';
      empty.textContent = 'No photos yet. (Ask an admin to sync the gallery.)';
      photoGrid.appendChild(empty);
      return;
    }

    const start = (currentPage - 1) * pageSize;
    const pageItems = filtered.slice(start, start + pageSize);

    pageItems.forEach((item, idx) => {
      const absoluteIndex = start + idx;

      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'gallery-item';
      card.style.cursor = 'pointer';
      card.setAttribute('aria-label', item.label || item.album || 'Open photo');

      const img = document.createElement('img');
      img.src = item.thumb || item.file;
      img.alt = item.label || item.album || 'Gallery photo';
      img.loading = 'lazy';

      const label = document.createElement('div');
      label.className = 'gallery-label';
      label.textContent = item.label || item.album || 'Photo';

      card.appendChild(img);
      card.appendChild(label);

      card.addEventListener('click', () => openLightbox(absoluteIndex));

      photoGrid.appendChild(card);
    });
  }

  async function loadGalleryJson() {
    try {
      // Prefer the live Worker feed (no more exporting files).
      // Fallback to the legacy static file for older deployments.
      let res = await fetch('/public/gallery.json', { cache: 'no-store' });
      if (!res.ok) res = await fetch('../gallery.json', { cache: 'no-store' });
      if (!res.ok) throw new Error('Gallery feed not found');
      const data = await res.json();
      allItems = normalizeItems(data.items || []);
    } catch {
      allItems = [];
    }

    buildAlbumOptions(allItems);
    filtered = [...allItems];
    applyFilters();
  }

  // Events
  prevPage.addEventListener('click', () => {
    currentPage = Math.max(1, currentPage - 1);
    render();
  });

  nextPage.addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    currentPage = Math.min(totalPages, currentPage + 1);
    render();
  });

  albumFilter.addEventListener('change', applyFilters);
  sortBy.addEventListener('change', applyFilters);
  tagSearch.addEventListener('input', () => {
    // debounce-ish
    window.clearTimeout(tagSearch._t);
    tagSearch._t = window.setTimeout(applyFilters, 120);
  });

  lbClose.addEventListener('click', closeLightbox);
  lbPrev.addEventListener('click', () => stepLightbox(-1));
  lbNext.addEventListener('click', () => stepLightbox(1));

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeLightbox();
  });

  document.addEventListener('keydown', (e) => {
    if (!overlay.classList.contains('visible')) return;
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowLeft') stepLightbox(-1);
    if (e.key === 'ArrowRight') stepLightbox(1);
  });

  loadGalleryJson();
})();
