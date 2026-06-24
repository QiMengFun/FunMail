import { api, saveToken } from './api.js';
import { loginPage } from './pages/login.js';
import { buildMailList } from './pages/maillist.js';
import { decodeSubject, fmtDate, fmtFullDate, fmtSize, escHtml } from './util.js';

export function webmailApp() {
  return {
    // 工具函数（暴露给 Alpine 模板）
    decodeSubject, fmtDate, fmtFullDate, fmtSize, escHtml,
    t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
    lang: window.getLang(),
    langOpen: false,

    // 主题
    isDark: document.documentElement.getAttribute('data-theme') === 'dark',
    toggleTheme() {
      this.isDark = !this.isDark;
      document.documentElement.setAttribute('data-theme', this.isDark ? 'dark' : 'light');
      localStorage.setItem('webmail_theme', this.isDark ? 'dark' : 'light');
      this.inbox.isDark = this.isDark;
      this.sent.isDark = this.isDark;
    },

    // 鉴权状态
    authed: false,
    user: null,
    authLoading: true,

    // 当前 tab: login | inbox | sent | compose
    page: 'login',
    mobileNavOpen: false,

    // 列表子 mixin
    inbox: buildMailList('inbox'),
    sent: buildMailList('sent'),

    // Webmail 权限
    canSend: true,          // 写邮件按钮是否可用（基于 allow_webmail）
    canReceive: true,       // 收件箱按钮是否可用（Webmail 始终可收件）
    // 协议权限（仅用于接入设置教程卡片显示）
    smtpAllowed: true,      // SMTP 协议状态
    pop3Allowed: true,      // POP3 协议状态
    imapAllowed: true,      // IMAP 协议状态
    setupInfo: {            // 接入设置信息
      smtp_host: '',
      pop3_host: '',
      imap_host: '',
    },
    // 写邮件
    composeTo: '',
    composeCc: '',
    composeSubject: '',
    composeBody: '',
    composeSending: false,
    composeSent: false,
    composeError: '',
    // 附件
    composeAttachments: [],  // {filename, content_type, content_base64, size}
    maxAttachmentSize: 25,   // MB
    // 联系人自动补全
    autocompleteList: [],
    autocompleteTarget: '',  // 'to' 或 'cc'
    // 联系人页
    contacts: [],
    contactsLoading: false,
    contactModalOpen: false,
    contactForm: { id: null, name: '', email: '', notes: '' },
    // 顶部搜索
    searchKeyword: '',
    searchResults: null,
    searchLoading: false,

    // 自定义页脚
    footerHtml: '',

    // 页面名 → URL 路径映射
    pageRoutes: {
      inbox: '/inbox',
      sent: '/sent',
      compose: '/compose',
      contacts: '/contacts',
      setup: '/setup',
      search: '/search',
    },

    // 从 URL 路径解析 page 名
    pageFromPath(path) {
      const p = path.replace(/\/+$/, '') || '/';
      // 根路径 / 也视为 inbox
      if (p === '/') return 'inbox';
      for (const [name, route] of Object.entries(this.pageRoutes)) {
        if (p === route) return name;
      }
      return 'inbox';
    },

    async init() {
      // 监听浏览器前进/后退
      window.addEventListener('popstate', () => {
        const p = this.pageFromPath(window.location.pathname);
        if (this.page !== p) this.setPage(p);
      });

      // 监听语言切换事件
      window.addEventListener('lang-changed', (e) => {
        this.lang = e.detail.lang;
      });

      // 监听子 mixin 的 pageNum 变化
      this.$watch('page', (v) => {
        this.mobileNavOpen = false;
        // 切换时清空搜索/分页
        if (v === 'inbox') { this.inbox.pageNum = 1; this.inbox.loadMails(); }
        if (v === 'sent')  { this.sent.pageNum = 1; this.sent.loadMails(); }
        if (v === 'compose') {
          // 从 URL 参数预填（?to=&subject=&body=）
          const q = new URLSearchParams(window.location.search);
          if (q.get('to') && !this.composeTo) this.composeTo = q.get('to');
          if (q.get('subject') && !this.composeSubject) this.composeSubject = q.get('subject');
          if (q.get('body') && !this.composeBody) this.composeBody = q.get('body');
        }
        // 滚动顶部
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });

      // 登录成功事件
      window.addEventListener('webmail-login', () => this.afterLogin());

      // 检查 token
      await this.checkAuth();

      // 加载自定义页脚
      try { this.footerHtml = await api.footer(); } catch {}
    },

    async checkAuth() {
      this.authLoading = true;
      try {
        const me = await api.me();
        this.user = me;
        this.authed = true;
        // 同步协议权限
        this.applyProtocolLimits(me);
        // 根据 URL 路径恢复页面，默认 inbox
        const urlPage = this.pageFromPath(window.location.pathname);
        this.page = urlPage;
        // 根路径 / 保持不变（就是 inbox），其他路径确保与 pageRoutes 一致
        const currentPath = window.location.pathname.replace(/\/+$/, '') || '/';
        if (currentPath !== '/' && currentPath !== (this.pageRoutes[urlPage] || '/inbox')) {
          history.replaceState(null, '', this.pageRoutes[urlPage] || '/inbox');
        }
      } catch {
        this.authed = false;
        this.page = 'login';
        // 未登录时将 URL 重置为根路径，避免登录页显示 /inbox 等路径
        if (window.location.pathname !== '/') {
          history.replaceState(null, '', '/');
        }
        this.canSend = true;
        this.canReceive = true;
        this.smtpAllowed = true;
        this.pop3Allowed = true;
        this.imapAllowed = true;
      } finally {
        this.authLoading = false;
      }
    },

    /// 根据 me 返回的 is_self_registered + register_config 计算协议权限
    applyProtocolLimits(me) {
      const cfg = (me && me.register_config) || {};

      // 计算服务器主机名：从邮箱地址提取域名，各协议使用独立子域名前缀
      const email = (me && me.email) || '';
      const domain = email.split('@')[1] || '';
      this.setupInfo = {
        smtp_host: domain ? `smtp.${domain}` : '',
        pop3_host: domain ? `pop.${domain}` : '',
        imap_host: domain ? `imap.${domain}` : '',
      };

      // 统一使用 allow_* 字段名（register_config 和 protocols 一致）
      const webmailAllowed = cfg.allow_webmail;
      const smtpAllowed = cfg.allow_smtp;
      const pop3Allowed = cfg.allow_pop3;
      const imapAllowed = cfg.allow_imap;

      // Webmail 功能只受 allow_webmail 控制
      this.canSend = webmailAllowed !== false;
      this.canReceive = true;
      // 协议状态仅用于接入设置教程卡片
      this.smtpAllowed = smtpAllowed !== false;
      this.pop3Allowed = pop3Allowed !== false;
      this.imapAllowed = imapAllowed !== false;
    },

    async afterLogin() {
      try {
        const me = await api.me();
        this.user = me;
        this.authed = true;
        this.applyProtocolLimits(me);
        const urlPage = this.pageFromPath(window.location.pathname);
        this.navigate(urlPage === 'login' ? 'inbox' : urlPage);
      } catch {
        saveToken(null);
        this.authed = false;
        this.page = 'login';
        if (window.location.pathname !== '/') {
          history.replaceState(null, '', '/');
        }
        this.canSend = true;
        this.canReceive = true;
        this.pop3Allowed = true;
        this.imapAllowed = true;
      }
    },

    async sendMail() {
      if (!this.canSend) return;
      this.composeError = '';
      this.composeSent = false;
      const to = (this.composeTo || '').split(/[,;\s]+/).filter(Boolean);
      const cc = (this.composeCc || '').split(/[,;\s]+/).filter(Boolean);
      if (to.length === 0) { this.composeError = this.t('wm_compose_error_empty_to'); return; }
      if (!this.composeSubject.trim()) { this.composeError = this.t('wm_compose_error_empty_subject'); return; }
      if (!this.composeBody.trim()) { this.composeError = this.t('wm_compose_error_empty_body'); return; }
      this.composeSending = true;
      try {
        const me = await api.me();
        this.maxAttachmentSize = me.max_attachment_size_mb || 25;
        const payload = {
          from_addr: me.email,
          to_addrs: to,
          cc_addrs: cc.length ? cc : undefined,
          subject: this.composeSubject,
          body_text: this.composeBody,
        };
        if (this.composeAttachments.length > 0) {
          payload.attachments = this.composeAttachments.map(a => ({
            filename: a.filename,
            content_type: a.content_type,
            content_base64: a.content_base64,
          }));
        }
        await api.send(payload);
        this.composeSent = true;
        // 发送成功后清除 URL 参数，避免刷新重复填入
        if (window.location.search) {
          history.replaceState(null, '', window.location.pathname);
        }
        this.composeTo = '';
        this.composeCc = '';
        this.composeSubject = '';
        this.composeBody = '';
        this.composeAttachments = [];
        setTimeout(() => { this.composeSent = false; }, 3000);
      } catch (e) {
        this.composeError = e?.message || this.t('wm_compose_error_send_failed');
      } finally {
        this.composeSending = false;
      }
    },

    async logout() {
      try { await api.logout(); } catch {}
      saveToken(null);
      this.user = null;
      this.authed = false;
      this.canSend = true;
      this.canReceive = true;
      this.smtpAllowed = true;
      this.pop3Allowed = true;
      this.imapAllowed = true;
      this.page = 'login';
      this.mobileNavOpen = false;
      history.replaceState(null, '', '/');
    },

    setPage(p) {
      this.page = p;
      if (p === 'contacts') this.loadContacts();
    },

    // 带路由的页面导航：更新 URL + 切换页面
    navigate(p) {
      if (typeof p === 'string' && this.pageRoutes[p]) {
        const path = this.pageRoutes[p];
        if (window.location.pathname !== path) {
          history.pushState(null, '', path);
        }
        this.setPage(p);
      } else {
        // 兜底：直接设置 page
        this.setPage(p);
      }
    },

    // ====== 联系人 ======
    async loadContacts() {
      this.contactsLoading = true;
      try {
        this.contacts = await api.contacts();
      } catch (e) {
        console.error('加载联系人失败', e);
      } finally {
        this.contactsLoading = false;
      }
    },

    openContactModal(contact = null) {
      if (contact) {
        this.contactForm = { id: contact.id, name: contact.name || '', email: contact.email, notes: contact.notes || '' };
      } else {
        this.contactForm = { id: null, name: '', email: '', notes: '' };
      }
      this.contactModalOpen = true;
    },

    async saveContact() {
      try {
        const data = {
          name: this.contactForm.name.trim() || null,
          email: this.contactForm.email.trim(),
          notes: this.contactForm.notes.trim() || null,
        };
        if (this.contactForm.id) {
          await api.updateContact(this.contactForm.id, data);
        } else {
          await api.addContact(data);
        }
        this.contactModalOpen = false;
        this.loadContacts();
      } catch (e) {
        alert(e.message || '保存失败');
      }
    },

    async deleteContact(id) {
      if (!confirm(this.t('wm_contacts_delete_confirm') || '确定删除此联系人？')) return;
      try {
        await api.deleteContact(id);
        this.loadContacts();
      } catch (e) {
        alert(e.message || '删除失败');
      }
    },

    // ====== 附件 ======
    onFileSelect(e) {
      const files = e.target.files;
      if (!files) return;
      const maxBytes = this.maxAttachmentSize * 1024 * 1024;
      for (const file of files) {
        if (file.size > maxBytes) {
          this.composeError = (this.t('wm_compose_attachment_too_large') || '附件不能超过') + ' ' + this.maxAttachmentSize + 'MB';
          continue;
        }
        const reader = new FileReader();
        reader.onload = () => {
          const base64 = reader.result.split(',')[1];
          this.composeAttachments.push({
            filename: file.name,
            content_type: file.type || 'application/octet-stream',
            content_base64: base64,
            size: file.size,
          });
        };
        reader.readAsDataURL(file);
      }
      e.target.value = '';
    },

    removeAttachment(idx) {
      this.composeAttachments.splice(idx, 1);
    },

    moveAttachment(idx, dir) {
      const newIdx = idx + dir;
      if (newIdx < 0 || newIdx >= this.composeAttachments.length) return;
      const arr = this.composeAttachments;
      [arr[idx], arr[newIdx]] = [arr[newIdx], arr[idx]];
    },

    fileIcon(contentType) {
      const t = (k) => this.t(k) || k;
      if (!contentType) return t('wm_file_type_file');
      if (contentType.startsWith('image/')) return t('wm_file_type_image');
      if (contentType.startsWith('video/')) return t('wm_file_type_video');
      if (contentType.startsWith('audio/')) return t('wm_file_type_audio');
      if (contentType.includes('pdf')) return 'PDF';
      if (contentType.includes('zip') || contentType.includes('rar') || contentType.includes('7z') || contentType.includes('tar') || contentType.includes('gz')) return 'ZIP';
      if (contentType.includes('word') || contentType.includes('msword') || contentType.includes('officedocument.wordprocessing')) return 'DOC';
      if (contentType.includes('excel') || contentType.includes('spreadsheet') || contentType.includes('officedocument.spreadsheet')) return 'XLS';
      if (contentType.includes('powerpoint') || contentType.includes('presentation') || contentType.includes('officedocument.presentation')) return 'PPT';
      if (contentType.startsWith('text/')) return t('wm_file_type_text');
      return t('wm_file_type_file');
    },

    formatSize(bytes) {
      if (!bytes) return '0 B';
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    },

    // ====== 联系人自动补全 ======
    onComposeInput(field) {
      this.autocompleteTarget = field;
      const val = field === 'to' ? this.composeTo : this.composeCc;
      // 取光标前最后一个邮箱地址片段
      const parts = val.split(/[,;\s]+/);
      const last = parts[parts.length - 1] || '';
      if (last.length < 1) {
        this.autocompleteList = [];
        return;
      }
      api.searchContacts(last).then(list => {
        this.autocompleteList = list || [];
      }).catch(() => { this.autocompleteList = []; });
    },

    pickAutocomplete(contact) {
      const name = contact.name ? `${contact.name} <${contact.email}>` : contact.email;
      if (this.autocompleteTarget === 'to') {
        const parts = this.composeTo.split(/[,;\s]+/);
        parts[parts.length - 1] = name;
        this.composeTo = parts.join(', ');
      } else {
        const parts = this.composeCc.split(/[,;\s]+/);
        parts[parts.length - 1] = name;
        this.composeCc = parts.join(', ');
      }
      this.autocompleteList = [];
    },

    // ====== 回复 / 转发 ======
    replyMail(detail) {
      this.inbox.closeDetail(); this.sent.closeDetail();
      this.composeAttachments = [];
      this.composeTo = detail.from_addr || '';
      this.composeCc = detail.cc_addrs || '';
      this.composeSubject = detail.subject.startsWith('Re: ') ? detail.subject : `Re: ${detail.subject}`;
      this.composeBody = `\n\n---------- ${this.t('wm_original_mail') || '原始邮件'} ----------\nFrom: ${detail.from_addr}\nTo: ${detail.to_addr}\nSubject: ${detail.subject}\n\n${detail.body_text || ''}`;
      this.navigate('compose');
    },

    replyAllMail(detail) {
      this.inbox.closeDetail(); this.sent.closeDetail();
      this.composeAttachments = [];
      const myEmail = (this.user && this.user.email) || '';
      // 收件人 = 原发件人 + 原收件人（去除自己）
      const all = [detail.from_addr, ...(detail.to_addr || '').split(',').map(s => s.trim())];
      const others = all.filter(e => e && e.toLowerCase() !== myEmail.toLowerCase());
      this.composeTo = others.join(', ');
      this.composeCc = detail.cc_addrs || '';
      this.composeSubject = detail.subject.startsWith('Re: ') ? detail.subject : `Re: ${detail.subject}`;
      this.composeBody = `\n\n---------- ${this.t('wm_original_mail') || '原始邮件'} ----------\nFrom: ${detail.from_addr}\nTo: ${detail.to_addr}\nSubject: ${detail.subject}\n\n${detail.body_text || ''}`;
      this.navigate('compose');
    },

    forwardMail(detail) {
      this.inbox.closeDetail(); this.sent.closeDetail();
      // 转发时携带原邮件附件（从详情数据加载 base64）
      this.composeAttachments = (detail.attachments || []).map(att => ({
        filename: att.filename,
        content_type: att.content_type,
        content_base64: '',  // 需异步下载
        size: att.size,
        _need_download: true,
        _mail_id: detail.id,
        _index: att.index,
      }));
      // 异步下载附件内容
      if (detail.attachments && detail.attachments.length > 0) {
        this.downloadAttachmentsForForward(detail.id, detail.attachments);
      }
      this.composeTo = '';
      this.composeCc = '';
      this.composeSubject = detail.subject.startsWith('Fwd: ') ? detail.subject : `Fwd: ${detail.subject}`;
      this.composeBody = `\n\n---------- ${this.t('wm_forwarded_mail') || '转发邮件'} ----------\nFrom: ${detail.from_addr}\nTo: ${detail.to_addr}\nSubject: ${detail.subject}\n\n${detail.body_text || ''}`;
      this.navigate('compose');
    },

    // 异步下载附件用于转发
    async downloadAttachmentsForForward(mailId, attachments) {
      const token = localStorage.getItem('webmail_token') || '';
      for (const att of attachments) {
        try {
          const res = await fetch(`/api/mail/attachment/${mailId}/${att.index}?token=${encodeURIComponent(token)}`);
          const blob = await res.blob();
          const base64 = await new Promise(resolve => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result.split(',')[1]);
            reader.readAsDataURL(blob);
          });
          const item = this.composeAttachments.find(a => a._mail_id === mailId && a._index === att.index);
          if (item) item.content_base64 = base64;
        } catch (e) {
          console.error('下载转发附件失败:', att.filename, e);
        }
      }
    },

    // ====== 全文搜索 ======
    async doSearch() {
      const kw = (this.searchKeyword || '').trim();
      if (!kw) { this.searchResults = null; return; }
      this.searchLoading = true;
      this.navigate('search');
      try {
        const token = localStorage.getItem('webmail_token') || '';
        const params = new URLSearchParams({ search: kw, page_size: 100 });
        // 搜收件箱
        const inboxData = await fetch('/api/mail/inbox?' + params, {
          headers: { 'Authorization': 'Bearer ' + token }
        }).then(r => r.json()).catch(() => ({ data: [] }));
        // 搜发件箱
        const sentData = await fetch('/api/mail/sent?' + params, {
          headers: { 'Authorization': 'Bearer ' + token }
        }).then(r => r.json()).catch(() => ({ data: [] }));
        const inboxMails = inboxData.data || [];
        const sentMails = sentData.data || [];
        // 合并并标记来源
        this.searchResults = [
          ...inboxMails.map(m => ({ ...m, _source: 'inbox' })),
          ...sentMails.map(m => ({ ...m, _source: 'sent' })),
        ];
      } catch (e) {
        console.error('搜索失败', e);
        this.searchResults = [];
      } finally {
        this.searchLoading = false;
      }
    },

    clearSearch() {
      this.searchKeyword = '';
      this.searchResults = null;
      this.navigate('inbox');
    },

    toggleMobileNav() {
      this.mobileNavOpen = !this.mobileNavOpen;
    },

    switchLang(lang) {
      window.setLang(lang);
      this.lang = lang;
      window.dispatchEvent(new CustomEvent('lang-changed', { detail: { lang } }));
    },
  };
}

// 暴露到 window，便于 Alpine x-data 引用
// Alpine 的 x-data 表达式在找不到作用域变量时会 fallback 到 window
// ES Module 内的 export const 默认不挂到 window，所以必须显式挂载
window.pageMixins = window.pageMixins || {};
window.pageMixins.webmailApp = webmailApp;
window.loginPage = loginPage;
