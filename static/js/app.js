/* ScamShield front-end: live check, AJAX voting, lightbox, uploads, copy/share. No libraries. */
(function () {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const csrf = () => (document.cookie.match(/csrftoken=([^;]+)/) || [])[1] || ($('[name=csrfmiddlewaretoken]') || {}).value;

  function toast(msg) {
    let t = $('#toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; document.body.appendChild(t); }
    t.textContent = msg; t.classList.add('show');
    clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2400);
  }
  window.ssToast = toast;

  /* mobile menu */
  const tog = $('.menu-toggle');
  if (tog) tog.addEventListener('click', () => $('.nav').classList.toggle('open'));

  /* dismiss messages */
  $$('.messages button').forEach((b) => b.addEventListener('click', () => b.parentElement.remove()));

  /* "/" focuses the search box */
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      const s = $('#q') || $('[name=q]'); if (s) { e.preventDefault(); s.focus(); s.select(); }
    }
  });

  /* ---------------- live check as you type ---------------- */
  function liveCheck(input, panel, opts = {}) {
    let timer, ctrl;
    const url = input.dataset.api || '/api/check/';
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 4) { panel.classList.remove('show'); return; }
      timer = setTimeout(async () => {
        if (ctrl) ctrl.abort(); ctrl = new AbortController();
        try {
          const r = await fetch(url + '?q=' + encodeURIComponent(q), { signal: ctrl.signal });
          const d = await r.json();
          if (!d.ready) return;
          render(d);
        } catch (e) { /* aborted */ }
      }, 280);
    });
    document.addEventListener('click', (e) => { if (!panel.contains(e.target) && e.target !== input) panel.classList.remove('show'); });
    input.addEventListener('focus', () => { if (panel.innerHTML.trim() && input.value.trim().length >= 4) panel.classList.add('show'); });

    function render(d) {
      const reports = d.reports.map((r) => `<li><a href="${esc(r.url)}">${esc(r.title)}</a><span class="badge badge-${r.status === 'confirmed' ? 'danger' : r.status === 'disputed' ? 'muted' : 'warn'}">${esc(r.status)}</span></li>`).join('');
      const signals = d.signals.slice(0, 3).map((s) => `<li><span>⚑ ${esc(s.label)}</span></li>`).join('');
      if (opts.mode === 'dupe') {
        if (!d.reports.length) { panel.classList.remove('show'); return; }
        panel.innerHTML = `<div class="card" style="border-left:4px solid var(--red)"><b>Already reported ${d.reports.length}×.</b> You can still file your report (it strengthens the evidence), or vote on an existing one:<ul class="live" style="position:static;display:block;box-shadow:none;border:0;padding:0">${reports}</ul></div>`;
        panel.classList.add('show'); return;
      }
      panel.innerHTML = `
        <div class="live-head">
          <div class="live-score ${esc(d.tone)}">${d.score}</div>
          <div><div class="kind">${esc(d.type)} · ${esc(d.normalized)}</div><b>${esc(d.verdict)}</b><div class="muted" style="font-size:.88rem">${esc(d.headline)}</div></div>
        </div>
        ${reports || signals ? `<ul>${reports}${signals}</ul>` : ''}
        <div style="margin-top:12px;display:flex;gap:8px"><a class="btn btn-dark btn-sm" href="${esc(d.search_url)}">Full results →</a>
        <a class="btn btn-ghost btn-sm" href="/report/new/?identifier=${encodeURIComponent(d.query)}">Report it</a></div>`;
      panel.classList.add('show');
    }
  }
  $$('[data-live]').forEach((inp) => {
    const panel = document.getElementById(inp.dataset.live);
    if (panel) liveCheck(inp, panel);
  });
  const identInput = $('[data-live-check]');
  if (identInput && $('#dupe-alert')) liveCheck(identInput, $('#dupe-alert'), { mode: 'dupe' });

  /* ---------------- AJAX voting ---------------- */
  const vb = $('#vote-box');
  if (vb) {
    vb.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = e.submitter; if (!btn) return;
      let choice = btn.value;
      if (btn.classList.contains('on')) choice = 'clear';
      const body = new URLSearchParams({ choice });
      $$('.vote-btn', vb).forEach((b) => (b.disabled = true));
      try {
        const r = await fetch(vb.action, { method: 'POST', body, headers: { 'X-CSRFToken': csrf(), 'X-Requested-With': 'XMLHttpRequest' } });
        const d = await r.json();
        if (!r.ok) { toast(d.error || 'Could not vote'); return; }
        $('.vote-btn.scam .n', vb).textContent = d.scam;
        $('.vote-btn.safe .n', vb).textContent = d.safe;
        $$('.vote-btn', vb).forEach((b) => b.classList.toggle('on', b.value === d.my_vote));
        $('#confidence-fill').style.width = d.confidence + '%';
        $('#confidence-num').textContent = d.confidence + '%';
        const badge = $('#status-badge');
        badge.textContent = d.status_label;
        badge.className = 'badge badge-' + ({ confirmed: 'danger', suspected: 'warn', disputed: 'muted' }[d.status]);
        if (d.status_changed) { badge.classList.add('status-flash'); toast('Status changed to ' + d.status_label + ' thanks to your vote!'); }
        else toast(d.my_vote ? 'Vote recorded. Thank you!' : 'Vote removed');
      } finally { $$('.vote-btn', vb).forEach((b) => (b.disabled = false)); }
    });
  }

  /* ---------------- copy + share ---------------- */
  $$('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    const text = b.dataset.copy;
    try { await navigator.clipboard.writeText(text); } catch (e) {
      const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    toast(b.dataset.copied || 'Copied to clipboard');
  }));
  $$('[data-share]').forEach((b) => b.addEventListener('click', async () => {
    const data = { title: b.dataset.title, text: b.dataset.text, url: b.dataset.url };
    if (navigator.share) { try { await navigator.share(data); return; } catch (e) { return; } }
    try { await navigator.clipboard.writeText(data.text + ' ' + data.url); toast('Warning copied. Paste it to your friend or group chat.'); } catch (e) {}
  }));

  /* ---------------- lightbox ---------------- */
  const lb = $('#lightbox');
  if (lb) {
    $$('.gallery a').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); $('img', lb).src = a.href; lb.classList.add('show'); }));
    lb.addEventListener('click', () => lb.classList.remove('show'));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') lb.classList.remove('show'); });
  }

  /* ---------------- drag & drop evidence ---------------- */
  const dz = $('.dropzone');
  if (dz) {
    const input = $('input[type=file]', dz), thumbs = $('#thumbs'), label = $('.dz-label', dz);
    dz.addEventListener('click', (e) => { if (e.target !== input) input.click(); });
    ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
    dz.addEventListener('drop', (e) => { input.files = e.dataTransfer.files; preview(); });
    input.addEventListener('change', preview);
    function preview() {
      thumbs.innerHTML = '';
      Array.from(input.files).forEach((f) => {
        if (!f.type.startsWith('image/')) return;
        const img = document.createElement('img'); img.src = URL.createObjectURL(f); img.title = f.name; thumbs.appendChild(img);
      });
      label.textContent = input.files.length ? `${input.files.length} image(s) selected` : 'Drop screenshots here or click to browse';
    }
  }

  /* ---------------- animate gauges ---------------- */
  $$('.gauge .fill').forEach((p) => {
    const target = p.getAttribute('stroke-dasharray');
    p.setAttribute('stroke-dasharray', '0 251.2');
    requestAnimationFrame(() => setTimeout(() => p.setAttribute('stroke-dasharray', target), 60));
  });
  $$('[data-count]').forEach((el) => {
    const end = parseFloat(el.dataset.count), prefix = el.dataset.prefix || '', dur = 900, t0 = performance.now();
    if (!isFinite(end)) return;
    (function tick(t) {
      const k = Math.min(1, (t - t0) / dur), v = Math.round(end * (1 - Math.pow(1 - k, 3)));
      el.textContent = prefix + v.toLocaleString();
      if (k < 1) requestAnimationFrame(tick);
    })(t0);
  });
})();
