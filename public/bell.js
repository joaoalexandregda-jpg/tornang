// ===== v6.1: sino compartilhado (abas, emergências, banner, polling) + ícones Lucide =====
(function () {
  const token = localStorage.getItem('token');
  if (!token) return;
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function refreshIcons() { if (window.lucide) lucide.createIcons(); }
  const TYPE_ICONS = { section_arrival: 'inbox', task_assigned: 'clipboard-list', late: 'calendar-clock', alert: 'alert-triangle', emergency: 'siren', join_request: 'user-plus', join_accepted: 'user-check', join_recused: 'user-x', step_done: 'check' };

  async function apiGet(path) {
    const res = await fetch(path, { headers: { 'Authorization': 'Bearer ' + token } });
    return res.json().catch(() => ({}));
  }
  let notifsCache = [], notifTab = 'all';
  let lastEmergId = Number(sessionStorage.getItem('lastEmergId') || 0);

  function tabOf(n) {
    if (n.type === 'join_request') return 'join';
    if (n.type === 'emergency') return 'emg';
    return 'alerts';
  }

  function render() {
    const panel = $('notifPanel');
    if (!panel) return;
    const list = notifsCache.filter(n => notifTab === 'all' || tabOf(n) === notifTab);
    const emgs = list.filter(n => n.type === 'emergency');
    const rest = list.filter(n => n.type !== 'emergency');
    const rows = [...emgs, ...rest].map(n => `
      <div class="notif-item ${n.type === 'emergency' ? 'note-emergency' : n.read ? '' : 'unread'}">
        <b><i data-lucide="${TYPE_ICONS[n.type] || 'bell'}"></i> ${esc(n.title)}</b>
        <p>${esc(n.body || '')}</p>
        <span class="when">${esc((n.created_at || '').slice(0, 16))}</span>
        ${n.type === 'emergency' && !n.read ? '<button class="emg-ack" data-id="' + n.id + '">✕ Entendido</button>' : ''}
      </div>`).join('');
    panel.innerHTML = `
      <div class="notif-tabs">
        <button data-tab="all" class="${notifTab === 'all' ? 'on' : ''}">Todas</button>
        <button data-tab="join" class="${notifTab === 'join' ? 'on' : ''}"><i data-lucide="user-plus"></i> Pedidos</button>
        <button data-tab="alerts" class="${notifTab === 'alerts' ? 'on' : ''}"><i data-lucide="alert-triangle"></i> Alertas</button>
        <button data-tab="emg" class="${notifTab === 'emg' ? 'on' : ''}"><i data-lucide="siren"></i> Emergências</button>
      </div>
      ${list.length ? rows : '<div class="notif-empty">Sem notificações por enquanto.</div>'}
      <div class="notif-actions"><button id="markAllRead">Marcar todas como lidas</button></div>`;
    refreshIcons();
    panel.querySelectorAll('.notif-tabs button').forEach(b => b.addEventListener('click', e => {
      e.stopPropagation(); notifTab = b.dataset.tab; render();
    }));
    panel.querySelectorAll('.emg-ack').forEach(b => b.addEventListener('click', async e => {
      e.stopPropagation();
      try { await fetch('/api/notifications/' + b.dataset.id + '/read', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); } catch (err) {}
      refresh();
    }));
    const mark = $('markAllRead');
    if (mark) mark.addEventListener('click', async e => {
      e.stopPropagation();
      try { await fetch('/api/notifications/read', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); } catch (err) {}
      refresh();
    });
  }

  function beep() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      [0, 0.35, 0.7].forEach(t => {
        const o = ctx.createOscillator(), g = ctx.createGain();
        o.frequency.value = 880; o.type = 'square'; o.connect(g); g.connect(ctx.destination);
        g.gain.setValueAtTime(0.25, ctx.currentTime + t);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + t + 0.25);
        o.start(ctx.currentTime + t); o.stop(ctx.currentTime + t + 0.25);
      });
    } catch (e) {}
  }

  function showBanner(n) {
    lastEmergId = Math.max(lastEmergId, n.id);
    sessionStorage.setItem('lastEmergId', String(lastEmergId));
    let banner = $('emgBanner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'emgBanner'; banner.className = 'emg-banner';
      document.body.prepend(banner);
    }
    banner.innerHTML = '<div><b>' + esc(n.title) + '</b><span> ' + esc(n.body || '') + '</span></div><button id="emgAck">✕ Entendido</button>';
    banner.hidden = false; beep();
    $('emgAck').addEventListener('click', async () => {
      banner.hidden = true;
      try { await fetch('/api/notifications/' + n.id + '/read', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); } catch (e) {}
      refresh();
    });
  }

  async function refresh() {
    try {
      const { notifications, unread } = await apiGet('/api/notifications');
      notifsCache = notifications || [];
      const badge = $('bellBadge');
      if (badge) { badge.textContent = unread; badge.hidden = unread === 0; }
      const newest = notifsCache.find(n => n.type === 'emergency' && !n.read && n.id > lastEmergId);
      if (newest) showBanner(newest);
      const panel = $('notifPanel');
      if (panel && !panel.hidden) render();
    } catch (e) {}
  }

  const bellBtn = $('bellBtn'), panel = $('notifPanel');
  if (bellBtn && panel) {
    bellBtn.addEventListener('click', e => {
      e.stopPropagation();
      panel.hidden = !panel.hidden;
      const um = $('userMenu'); if (um) um.hidden = true;
      if (!panel.hidden) render();
    });
    document.addEventListener('click', e => { if (!e.target.closest('.bell-wrap')) panel.hidden = true; });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') panel.hidden = true; });
  }
  refresh();
  setInterval(refresh, 20000);
})();