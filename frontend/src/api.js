const API_BASE = '/api';

// 后端中文错误消息 → i18n key 映射
const ERROR_I18N_MAP = {
  '只读用户无权执行此操作': 'viewer_write_denied',
  '禁止删除当前登录账号': 'err_delete_self',
  '禁止删除最后一个管理员': 'err_delete_last_admin',
  'admin 账号禁止删除': 'err_delete_admin',
  '用户不存在': 'err_user_not_found',
  '域名已存在': 'err_domain_exists',
  '邮箱已存在': 'err_mailbox_exists',
  '证书不存在': 'err_cert_not_found',
  '用户名或密码错误': 'err_login_failed',
  '登录已过期，请重新登录': 'err_token_expired',
  '未登录': 'err_not_logged_in',
  '当前用户不存在': 'err_current_user_not_found',
};

function translateError(msg) {
  const key = ERROR_I18N_MAP[msg];
  if (key && window.translations) {
    const lang = window.getLang ? window.getLang() : 'zh';
    const t = (window.translations[lang] && window.translations[lang][key]);
    if (t) return t;
  }
  return msg;
}

const api = {
  token: localStorage.getItem('funmail_token'),

  headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.token) { h['Authorization'] = `Bearer ${this.token}`; }
    return h;
  },

  async request(method, url, data) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (this.token && !url.includes('/auth/login')) { opts.headers['Authorization'] = `Bearer ${this.token}`; }
    if (data) { opts.body = JSON.stringify(data); }
    const resp = await fetch(`${API_BASE}${url}`, opts);
    if (resp.status === 401) {
      if (url.includes('/auth/login')) {
        throw new Error(translateError('用户名或密码错误'));
      }
      this.clearToken();
      if (window.location.pathname !== '/login') {
        history.pushState(null, '', '/login');
        window.dispatchEvent(new PopStateEvent('popstate'));
      }
      throw new Error(translateError('登录已过期，请重新登录'));
    }
    const text = await resp.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    if (!resp.ok) {
      const rawMsg = json?.error || json?.message || (json ? null : text) || `请求失败 (${resp.status})`;
      throw new Error(translateError(rawMsg));
    }
    return json;
  },

  get(url) { return this.request('GET', url); },
  post(url, data) { return this.request('POST', url, data); },
  put(url, data) { return this.request('PUT', url, data); },
  patch(url, data) { return this.request('PATCH', url, data); },
  delete(url) { return this.request('DELETE', url); },

  setToken(t) { this.token = t; localStorage.setItem('funmail_token', t); },
  clearToken() { this.token = null; localStorage.removeItem('funmail_token'); },
};

window.api = api;
