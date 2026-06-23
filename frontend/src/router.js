const routeKeys = [
  { path: '/login', titleKey: 'login', page: 'login' },
  { path: '/dashboard', titleKey: 'nav_dashboard', page: 'dashboard' },
  { path: '/domains', titleKey: 'nav_domains', page: 'domains' },
  { path: '/mailboxes', titleKey: 'nav_mailboxes', page: 'mailboxes' },
  { path: '/inbox', titleKey: 'nav_inbox', page: 'inbox' },
  { path: '/sent', titleKey: 'nav_sent', page: 'sent' },
  { path: '/compose', titleKey: 'nav_compose', page: 'compose' },
  { path: '/certs', titleKey: 'nav_certs', page: 'certs' },
  { path: '/queue', titleKey: 'nav_queue', page: 'queue' },
  { path: '/logs', titleKey: 'nav_logs', page: 'logs' },
  { path: '/settings', titleKey: 'nav_settings', page: 'settings' },
  { path: '/accounts', titleKey: 'nav_accounts', page: 'accounts' },
];

function matchRouteByPath(path) {
  for (const r of routeKeys) {
    const rParts = r.path.split('/');
    const pParts = path.split('/');
    if (rParts.length !== pParts.length) { continue; }
    let match = true;
    const params = {};
    for (let i = 0; i < rParts.length; i++) {
      if (rParts[i].startsWith(':')) {
        params[rParts[i].slice(1)] = decodeURIComponent(pParts[i]);
      } else if (rParts[i] !== pParts[i]) {
        match = false;
        break;
      }
    }
    if (match) { return { ...r, title: t(r.titleKey) }; }
  }
  return null;
}

window.router = { routes: routeKeys, matchRouteByPath };
