// ===== v5.9.5: rail compartilhado (logo + locais + flyout + railToggle) =====
(function () {
  const token = localStorage.getItem('token');
  if (!token) return;
  const rail = document.getElementById('rail');
  if (!rail) return;
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Logo
  fetch('/api/company', { headers: { 'Authorization': 'Bearer ' + token } })
    .then(r => r.json())
    .then(({ company }) => { const el = $('railLogo'); if (el && company && company.logo) el.innerHTML = `<img src="/${esc(company.logo)}" alt="">`; })
    .catch(() => {});

  // Flyout: usa o estático da página se existir, senão cria
  let flyout = $('flyout');
  const staticLinks = !!flyout;
  if (!flyout) {
    flyout = document.createElement('div');
    flyout.id = 'flyout'; flyout.className = 'flyout'; flyout.hidden = true;
    rail.appendChild(flyout);
  }
  const box = $('locIcons');
  if (!box) return;

  let hoverTimer = null, hideTimer = null;
  const scheduleHide = () => { clearTimeout(hideTimer); hideTimer = setTimeout(() => { flyout.hidden = true; }, 900); };
  const setLinks = l => {
    if (staticLinks) {
      $('flyoutTitle').textContent = l.name;
      $('flyProjects').href = 'manager.html?loc=' + l.id + '&tab=projects';
      $('flySections').href = 'manager.html?loc=' + l.id + '&tab=sections';
      $('flyGroups').href = 'manager.html?loc=' + l.id + '&tab=workers';
    } else {
      flyout.innerHTML = `<div class="flyout-title">${esc(l.name)}</div>
        <a class="flyout-link" href="manager.html?loc=${l.id}&tab=projects"><i data-lucide="folder"></i> Projetos</a>
        <a class="flyout-link" href="manager.html?loc=${l.id}&tab=sections"><i data-lucide="layers"></i> Seções</a>
        <a class="flyout-link" href="manager.html?loc=${l.id}&tab=workers"><i data-lucide="users"></i> Trabalhadores</a>`;
      window.lucide && lucide.createIcons();
    }
  };
  const show = (l, item) => {
    clearTimeout(hoverTimer); setLinks(l);
    flyout.style.top = item.offsetTop + 'px';
    flyout.style.left = (rail.offsetWidth - 4) + 'px';
    flyout.hidden = false;
  };

  flyout.addEventListener('mouseenter', () => clearTimeout(hideTimer));
  flyout.addEventListener('mouseleave', scheduleHide);
  rail.addEventListener('mouseleave', scheduleHide);
  rail.addEventListener('mouseenter', () => clearTimeout(hideTimer));
  $('railToggle')?.addEventListener('click', () => { rail.classList.toggle('expanded'); document.body.classList.toggle('rail-open'); });
  $('driversBtn')?.addEventListener('click', () => alert('Gerenciar Motoristas chega em uma próxima etapa.'));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') flyout.hidden = true; });
  document.addEventListener('click', e => { if (!e.target.closest('.rail') && !e.target.closest('.flyout')) flyout.hidden = true; });

  let locs = [];
  function renderLocs() {
    const currentLoc = new URLSearchParams(location.search).get('loc');
    box.innerHTML = locs.map(l => `
      <button class="rail-item loc${currentLoc == l.id ? ' active' : ''}" data-loc="${l.id}" title="${esc(l.name)}">
        ${l.image ? `<img src="${esc(l.image)}" alt="">` : esc((l.name || '?').trim()[0].toUpperCase())}
        <span class="rail-label">${esc(l.name)}</span>
      </button>`).join('');
    box.querySelectorAll('.rail-item').forEach(item => {
      const l = locs.find(x => String(x.id) === item.dataset.loc);
      if (!l) return;
      item.addEventListener('mouseenter', () => { clearTimeout(hideTimer); clearTimeout(hoverTimer); hoverTimer = setTimeout(() => show(l, item), 200); });
      item.addEventListener('mouseleave', () => { clearTimeout(hoverTimer); scheduleHide(); });
      item.addEventListener('click', () => show(l, item));
    });
  }
  async function reload() {
    try {
      const res = await fetch('/api/locations', { headers: { 'Authorization': 'Bearer ' + token } });
      const data = await res.json().catch(() => ({}));
      locs = data.locations || data || [];
      renderLocs();
    } catch (e) {}
  }
  reload();
  window.railRefresh = reload; // chamado pelas páginas após criar/editar/excluir local
})();