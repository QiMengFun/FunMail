// Webmail API 客户端（fetch 封装）
// 同样运行在 mail.* 子域名下，与管理后台共享 :10002 端口 → 所有请求走 /api/* 路径
const BASE = '/api';

function getToken() {
  return localStorage.getItem('webmail_token') || '';
}

async function request(path, { method = 'GET', body, headers = {} } = {}) {
  const token = getToken();
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...headers,
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : await res.text();
  // 登录 API 错误也返回 200，通过 data.error 判断
  if (data && data.error) {
    const err = new Error(data.error);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  if (!res.ok) {
    // 401 = token 失效（密码修改/被禁用/被删除），自动登出
    if (res.status === 401 && token) {
      localStorage.removeItem('webmail_token');
      // 延迟跳转，避免在初始化阶段竞态
      setTimeout(() => { window.location.href = '/'; }, 500);
    }
    const msg = (data && data.error) || (typeof data === 'string' ? data : `HTTP ${res.status}`);
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// 构造查询串：跳过 undefined / null / 空字符串，避免被序列化成 "undefined"
function buildQuery(params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    sp.append(k, v);
  }
  return sp.toString();
}

export const api = {
  // 登录/会话
  login: (email, password) => request('/webmail/login', { method: 'POST', body: { email, password } }),
  logout: () => request('/webmail/logout', { method: 'POST' }),
  me: () => request('/webmail/me'),

  // 邮件
  inbox: (params = {}) => {
    const q = buildQuery(params);
    return request('/mail/inbox' + (q ? '?' + q : ''));
  },
  sent: (params = {}) => {
    const q = buildQuery(params);
    return request('/mail/sent' + (q ? '?' + q : ''));
  },
  detail: (id) => request('/mail/detail/' + id),
  send: (payload) => request('/mail/send', { method: 'POST', body: payload }),
  attachmentUrl: (id, index) => {
    const token = getToken();
    return `${BASE}/mail/attachment/${id}/${index}?token=${encodeURIComponent(token)}`;
  },

  // 联系人
  contacts: () => request('/contacts'),
  addContact: (data) => request('/contacts', { method: 'POST', body: data }),
  updateContact: (id, data) => request('/contacts/' + id, { method: 'PUT', body: data }),
  deleteContact: (id) => request('/contacts/' + id, { method: 'DELETE' }),
  searchContacts: (q) => request('/contacts/search?q=' + encodeURIComponent(q)),

  // 全文搜索（搜收件箱）
  search: (keyword, params = {}) => {
    const sp = new URLSearchParams({ search: keyword, ...params });
    return request('/mail/inbox?' + sp.toString());
  },

  // 页脚（公开接口，不需要 token）
  footer: () => fetch('/api/webmail/footer').then(r => r.json()).then(d => d.html || '').catch(() => ''),

  // 网站名称（公开接口，不需要 token）
  siteName: () => fetch('/api/webmail/site-name').then(r => r.json()).then(d => d.name || '').catch(() => ''),
};

export function saveToken(t) {
  if (t) localStorage.setItem('webmail_token', t);
  else localStorage.removeItem('webmail_token');
}
