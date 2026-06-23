window.pageMixins = window.pageMixins || {};

// 收件列表
window.pageMixins.inbox = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  mails: [],
  total: 0,
  pageNum: 1,
  pageSize: 50,
  search: '',
  status: '',
  mailbox: '',
  domain: '',
  hours: 168,
  domains: [],

  async loadDomains() {
    try {
      this.domains = await api.get('/domains');
    } catch (e) {
      console.error('加载域名失败', e);
    }
  },

  async loadMails() {
    try {
      const params = new URLSearchParams();
      if (this.search) params.append('search', this.search);
      if (this.status) params.append('status', this.status);
      if (this.mailbox) params.append('mailbox', this.mailbox);
      if (this.domain) params.append('domain', this.domain);
      params.append('hours', this.hours);
      params.append('page', this.pageNum);
      params.append('page_size', this.pageSize);
      const data = await api.get('/mail/inbox?' + params.toString());
      this.mails = data.data || [];
      this.total = data.total || 0;
    } catch (e) {
      console.error('加载收件列表失败', e);
    }
  },

  async searchMails() {
    this.pageNum = 1;
    await this.loadMails();
  },

  async prevPage() {
    if (this.pageNum > 1) { this.pageNum--; await this.loadMails(); }
  },

  async nextPage() {
    if (this.pageNum * this.pageSize < this.total) { this.pageNum++; await this.loadMails(); }
  },

  statusBadge(s) {
    const map = { delivered: 'badge-success', bounced: 'badge-danger', blocked: 'badge-danger', queued: 'badge-info', deferred: 'badge-warning' };
    return map[s] || 'badge-info';
  },

  statusText(s) {
    const map = { delivered: this.t('mail_delivered'), bounced: this.t('mail_bounced'), blocked: this.t('mail_blocked'), queued: this.t('mail_status_queued'), deferred: this.t('mail_deferred') };
    return map[s] || s;
  },

  formatTime(t) {
    if (!t) return '-';
    return new Date(t).toLocaleString(this.lang === 'zh' ? 'zh-CN' : 'en-US');
  },

  formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  },

  // 解析 RFC 2047 编码主题（=?charset?B?base64?= 或 =?charset?Q?quoted-printable?=）
  decodeSubject(s) {
    if (!s || s.indexOf('=?') === -1) return s || '';
    return s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s*)/g, (_, charset, enc, text, trail) => {
      try {
        let bytes;
        if (enc === 'B' || enc === 'b') {
          // base64
          const cleaned = text.replace(/\s+/g, '');
          bytes = Uint8Array.from(atob(cleaned), c => c.charCodeAt(0));
        } else {
          // Q encoding: _ 代表空格，=XX 是 hex
          const replaced = text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
          bytes = new TextEncoder().encode(replaced);
        }
        // 用 TextDecoder 按 charset 解码（utf-8 / gb2312 / gbk 等）
        const decoded = new TextDecoder(charset.trim().toLowerCase() === 'gb2312' ? 'gbk' : charset.trim().toLowerCase()).decode(bytes);
        return decoded + trail;
      } catch (e) {
        return text;
      }
    });
  },

  // 邮件详情模态框状态
  detailOpen: false,
  detailLoading: false,
  detail: null,
  detailError: '',
  tab: 'html',

  async openDetail(id) {
    this.detailOpen = true;
    this.detailLoading = true;
    this.detail = null;
    this.detailError = '';
    try {
      this.detail = await api.get('/mail/detail/' + id);
    } catch (e) {
      this.detailError = e.message || this.t('mail_detail_loading');
    } finally {
      this.detailLoading = false;
    }
  },

  closeDetail() {
    this.detailOpen = false;
    this.detail = null;
    this.detailError = '';
  },

  decodeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
            .replace(/\n/g, '<br>');
  },

  // 渲染 HTML 详情到 iframe（使用 sandbox 禁 JS）
  renderHtmlIframe() {
    const html = this.detail?.body_html || '';
    if (!html) return '';
    // 套上最小化基础样式，避免外部 CSS 污染
    return `<!doctype html><html><head><meta charset="utf-8">
<base target="_blank">
<style>body{margin:0;padding:12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;color:#222;line-height:1.5}a{color:#2563eb}</style>
</head><body>${html}</body></html>`;
  }
};

// 发件列表
window.pageMixins.sent = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  mails: [],
  total: 0,
  pageNum: 1,
  pageSize: 50,
  search: '',
  status: '',
  mailbox: '',
  domain: '',
  hours: 168,
  domains: [],

  async loadDomains() {
    try {
      this.domains = await api.get('/domains');
    } catch (e) {
      console.error('加载域名失败', e);
    }
  },

  async loadMails() {
    try {
      const params = new URLSearchParams();
      if (this.search) params.append('search', this.search);
      if (this.status) params.append('status', this.status);
      if (this.mailbox) params.append('mailbox', this.mailbox);
      if (this.domain) params.append('domain', this.domain);
      params.append('hours', this.hours);
      params.append('page', this.pageNum);
      params.append('page_size', this.pageSize);
      const data = await api.get('/mail/sent?' + params.toString());
      this.mails = data.data || [];
      this.total = data.total || 0;
    } catch (e) {
      console.error('加载发件列表失败', e);
    }
  },

  async searchMails() {
    this.pageNum = 1;
    await this.loadMails();
  },

  async prevPage() {
    if (this.pageNum > 1) { this.pageNum--; await this.loadMails(); }
  },

  async nextPage() {
    if (this.pageNum * this.pageSize < this.total) { this.pageNum++; await this.loadMails(); }
  },

  statusBadge(s) {
    const map = { delivered: 'badge-success', bounced: 'badge-danger', blocked: 'badge-danger', queued: 'badge-info', deferred: 'badge-warning' };
    return map[s] || 'badge-info';
  },

  statusText(s) {
    const map = { delivered: this.t('mail_delivered'), bounced: this.t('mail_bounced'), blocked: this.t('mail_blocked'), queued: this.t('mail_status_queued'), deferred: this.t('mail_deferred') };
    return map[s] || s;
  },

  formatTime(t) {
    if (!t) return '-';
    return new Date(t).toLocaleString(this.lang === 'zh' ? 'zh-CN' : 'en-US');
  },

  formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  },

  // 解析 RFC 2047 编码主题（=?charset?B?base64?= 或 =?charset?Q?quoted-printable?=）
  decodeSubject(s) {
    if (!s || s.indexOf('=?') === -1) return s || '';
    return s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s*)/g, (_, charset, enc, text, trail) => {
      try {
        let bytes;
        if (enc === 'B' || enc === 'b') {
          // base64
          const cleaned = text.replace(/\s+/g, '');
          bytes = Uint8Array.from(atob(cleaned), c => c.charCodeAt(0));
        } else {
          // Q encoding: _ 代表空格，=XX 是 hex
          const replaced = text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
          bytes = new TextEncoder().encode(replaced);
        }
        // 用 TextDecoder 按 charset 解码（utf-8 / gb2312 / gbk 等）
        const decoded = new TextDecoder(charset.trim().toLowerCase() === 'gb2312' ? 'gbk' : charset.trim().toLowerCase()).decode(bytes);
        return decoded + trail;
      } catch (e) {
        return text;
      }
    });
  },

  // 邮件详情模态框状态
  detailOpen: false,
  detailLoading: false,
  detail: null,
  detailError: '',
  tab: 'html',

  async openDetail(id) {
    this.detailOpen = true;
    this.detailLoading = true;
    this.detail = null;
    this.detailError = '';
    try {
      this.detail = await api.get('/mail/detail/' + id);
    } catch (e) {
      this.detailError = e.message || this.t('mail_detail_loading');
    } finally {
      this.detailLoading = false;
    }
  },

  closeDetail() {
    this.detailOpen = false;
    this.detail = null;
    this.detailError = '';
  },

  decodeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
            .replace(/\n/g, '<br>');
  },

  renderHtmlIframe() {
    const html = this.detail?.body_html || '';
    if (!html) return '';
    return `<!doctype html><html><head><meta charset="utf-8">
<base target="_blank">
<style>body{margin:0;padding:12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;color:#222;line-height:1.5}a{color:#2563eb}</style>
</head><body>${html}</body></html>`;
  }
};

// 发送邮件
window.pageMixins.compose = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  domains: [],
  mailboxes: [],
  fromAddr: '',
  toAddrs: '',
  ccAddrs: '',
  subject: '',
  bodyType: 'html',
  bodyText: '',
  bodyHtml: '',
  sending: false,

  async loadDomains() {
    try {
      this.domains = await api.get('/domains');
      // 加载所有邮箱
      this.mailboxes = await api.get('/mailboxes');
      if (this.mailboxes.length > 0 && !this.fromAddr) {
        this.fromAddr = this.mailboxes[0].username + '@' + this.mailboxes[0].domain_name;
      }
    } catch (e) {
      console.error('加载域名/邮箱失败', e);
    }
  },

  async sendMail() {
    if (!this.fromAddr) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('mail_select_sender'), type: 'error' } }));
      return;
    }
    if (!this.toAddrs.trim()) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('mail_compose_to_label'), type: 'error' } }));
      return;
    }
    if (!this.subject.trim()) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('mail_compose_subject_label'), type: 'error' } }));
      return;
    }

    const toList = this.toAddrs.split(/[,;，；]/).map(s => s.trim()).filter(Boolean);
    const ccList = this.ccAddrs ? this.ccAddrs.split(/[,;，；]/).map(s => s.trim()).filter(Boolean) : [];

    // 验证邮箱格式
    const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    for (const addr of [...toList, ...ccList]) {
      if (!emailReg.test(addr)) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_invalid_email').replace('{addr}', addr), type: 'error' } }));
        return;
      }
    }

    this.sending = true;
    try {
      const data = {
        from_addr: this.fromAddr,
        to_addrs: toList,
        cc_addrs: ccList.length > 0 ? ccList : undefined,
        subject: this.subject,
        body_text: this.bodyType === 'text' ? this.bodyText : undefined,
        body_html: this.bodyType === 'html' ? this.bodyHtml : undefined,
      };
      const result = await api.post('/mail/send', data);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: result.message, type: 'success' } }));
      // 清空表单
      this.toAddrs = '';
      this.ccAddrs = '';
      this.subject = '';
      this.bodyText = '';
      this.bodyHtml = '';
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_send_failed').replace('{msg}', e.message), type: 'error' } }));
    } finally {
      this.sending = false;
    }
  }
};
