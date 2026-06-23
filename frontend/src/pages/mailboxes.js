window.pageMixins = window.pageMixins || {};

window.pageMixins.mailboxes = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  mailboxes: [],
  domains: [],
  showAdd: false,
  newMailbox: {
    domain_id: '',
    username: '',
    password: '',
    quota_mb: 1024,
    forward_to: '',
    keep_copy: true,
    is_admin: false,
    // 协议权限：默认勾全开（也允许直接传 null=继承域名）
    _enableProtocols: true,
    _smtp: true,
    _pop3: true,
    _imap: true,
    _forward: true,
    _webmail: true,
  },
  editingId: null,
  editForm: {},

  // ====== 协议侧边栏（编辑/覆盖单个邮箱的协议） ======
  showProtoPanel: false,
  protoMailbox: null,
  protoText: '',
  protoError: '',
  protoTab: 'form',     // 'form' | 'json'
  protoForm: {
    inherit: true,      // true = 继承域名；false = 覆盖
    smtp: true,
    pop3: true,
    imap: true,
    forward: true,
    webmail: true,
  },

  async loadMailboxes() {
    try {
      this.mailboxes = await api.get('/mailboxes');
    } catch (e) {
      console.error('加载邮箱失败', e);
    }
  },

  async loadDomains() {
    try {
      this.domains = await api.get('/domains');
      if (this.domains.length > 0 && !this.newMailbox.domain_id) {
        this.newMailbox.domain_id = this.domains[0].id;
      }
    } catch (e) {
      console.error('加载域名失败', e);
    }
  },

  /// 计算"实际生效"的协议集合，用于前端展示和协议徽标
  effectiveProtocols(m) {
    // 邮箱本身存了 protocols（非空对象）→ 覆盖
    const mp = m && m.protocols;
    if (mp && typeof mp === 'object' && !Array.isArray(mp) && Object.keys(mp).length > 0) {
      return {
        smtp:    (mp.allow_smtp    ?? mp.smtp)    !== false,
        pop3:    (mp.allow_pop3    ?? mp.pop3)    !== false,
        imap:    (mp.allow_imap    ?? mp.imap)    !== false,
        forward: (mp.allow_forward ?? mp.forward) !== false,
        webmail: (mp.allow_webmail ?? mp.webmail) !== false,
        source: 'custom',
      };
    }
    // 否则回落到该邮箱所属域名的 register_config
    const d = (this.domains || []).find(x => x.id === m.domain_id);
    const cfg = (d && d.register_config) || {};
    return {
      smtp:    cfg.allow_smtp  !== false,
      pop3:    cfg.allow_pop3  !== false,
      imap:    cfg.allow_imap  !== false,
      forward: cfg.allow_forward !== false,
      webmail: true,            // 域名级 webmail 始终允许
      source: 'inherited',
    };
  },

  protoBadges(m) {
    const p = this.effectiveProtocols(m);
    return [
      { k: 'SMTP',  ok: p.smtp,    title: this.t('mailboxes_protocol_smtp') },
      { k: 'POP3',  ok: p.pop3,    title: this.t('mailboxes_protocol_pop3') },
      { k: 'IMAP',  ok: p.imap,    title: this.t('mailboxes_protocol_imap') },
      { k: 'FWD',   ok: p.forward, title: this.t('mailboxes_protocol_forward') },
      { k: 'WEB',   ok: p.webmail, title: this.t('mailboxes_protocol_web_login') },
    ];
  },

  // ====== 创建 ======
  async addMailbox() {
    try {
      const data = { ...this.newMailbox };
      if (data.forward_to) {
        data.forward_to = JSON.stringify(data.forward_to.split(',').map(s => s.trim()).filter(Boolean));
      } else {
        data.forward_to = JSON.stringify([]);
      }
      // 协议：勾选启用则传对象（覆盖），否则不传（继承）
      if (data._enableProtocols) {
        data.protocols = {
          smtp:    !!data._smtp,
          pop3:    !!data._pop3,
          imap:    !!data._imap,
          forward: !!data._forward,
          webmail: !!data._webmail,
        };
      } else {
        data.protocols = null;
      }
      // 清理前端内部字段
      delete data._enableProtocols; delete data._smtp; delete data._pop3;
      delete data._imap; delete data._forward; delete data._webmail;
      await api.post('/mailboxes', data);
      this.showAdd = false;
      this.newMailbox = {
        domain_id: this.domains[0]?.id || '',
        username: '', password: '', quota_mb: 1024, forward_to: '', keep_copy: true, is_admin: false,
        _enableProtocols: true, _smtp: true, _pop3: true, _imap: true, _forward: true, _webmail: true,
      };
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_mail_created'), type: 'success' } }));
      this.loadMailboxes();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // ====== 编辑基本信息（内联表单） ======
  startEdit(m) {
    this.editingId = m.id;
    this.editForm = {
      quota_mb: m.quota_mb,
      enabled: m.enabled,
      keep_copy: m.keep_copy,
      is_admin: m.is_admin,
    };
  },

  async saveEdit(id) {
    try {
      await api.put(`/mailboxes/${id}`, this.editForm);
      this.editingId = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_mail_updated'), type: 'success' } }));
      this.loadMailboxes();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async resetPassword(id) {
    const newPass = prompt(this.t('toast_enter_password'));
    if (!newPass) return;
    try {
      await api.put(`/mailboxes/${id}`, { password: newPass });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_password_reset'), type: 'success' } }));
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async deleteMailbox(id, addr) {
    if (!confirm(this.t('confirm_delete_mailbox').replace('{addr}', addr))) return;
    try {
      await api.delete(`/mailboxes/${id}`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_mail_deleted'), type: 'success' } }));
      this.loadMailboxes();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  cancelEdit() { this.editingId = null; },

  // ====== 协议侧边栏 ======
  openProtoPanel(m) {
    this.protoMailbox = m;
    this.protoError = '';
    this.protoTab = 'form';
    // 判断当前是继承还是覆盖
    const mp = m.protocols;
    if (mp && typeof mp === 'object' && !Array.isArray(mp) && Object.keys(mp).length > 0) {
      this.protoForm.inherit = false;
      this.protoForm.smtp    = (mp.allow_smtp    ?? mp.smtp)    !== false;
      this.protoForm.pop3    = (mp.allow_pop3    ?? mp.pop3)    !== false;
      this.protoForm.imap    = (mp.allow_imap    ?? mp.imap)    !== false;
      this.protoForm.forward = (mp.allow_forward ?? mp.forward) !== false;
      this.protoForm.webmail = (mp.allow_webmail ?? mp.webmail) !== false;
    } else {
      const p = this.effectiveProtocols(m);
      this.protoForm.inherit = true;
      this.protoForm.smtp    = p.smtp;
      this.protoForm.pop3    = p.pop3;
      this.protoForm.imap    = p.imap;
      this.protoForm.forward = p.forward;
      this.protoForm.webmail = p.webmail;
    }
    this.protoText = JSON.stringify(this._protoToJson(), null, 2);
    this.showProtoPanel = true;
  },

  closeProtoPanel() {
    this.showProtoPanel = false;
    this.protoMailbox = null;
  },

  _protoToJson() {
    if (this.protoForm.inherit) return null;  // 继承：不存对象
    return {
      allow_smtp:    !!this.protoForm.smtp,
      allow_pop3:    !!this.protoForm.pop3,
      allow_imap:    !!this.protoForm.imap,
      allow_forward: !!this.protoForm.forward,
      allow_webmail: !!this.protoForm.webmail,
    };
  },

  syncProtoFromText() {
    try {
      const obj = this.protoText.trim() ? JSON.parse(this.protoText) : null;
      this.protoError = '';
      if (obj === null) {
        this.protoForm.inherit = true;
        return null;
      }
      if (typeof obj !== 'object' || Array.isArray(obj)) {
        this.protoError = this.t('json_must_be_object');
        return null;
      }
      this.protoForm.inherit = false;
      this.protoForm.smtp    = (obj.allow_smtp    ?? obj.smtp)    !== false;
      this.protoForm.pop3    = (obj.allow_pop3    ?? obj.pop3)    !== false;
      this.protoForm.imap    = (obj.allow_imap    ?? obj.imap)    !== false;
      this.protoForm.forward = (obj.allow_forward ?? obj.forward) !== false;
      this.protoForm.webmail = (obj.allow_webmail ?? obj.webmail) !== false;
      return obj;
    } catch (e) {
      this.protoError = this.t('json_parse_failed').replace('{msg}', e.message);
      return null;
    }
  },

  switchProtoTab(tab) {
    this.protoTab = tab;
    if (tab === 'json') {
      this.protoText = JSON.stringify(this._protoToJson(), null, 2);
    }
  },

  async saveProto() {
    if (!this.protoMailbox) return;
    let payload;
    if (this.protoTab === 'form') {
      // 继承 = 传空对象 → 后端会清空
      if (this.protoForm.inherit) {
        payload = { protocols: {} };
      } else {
        payload = { protocols: this._protoToJson() };
      }
    } else {
      // JSON
      try {
        const obj = this.protoText.trim() ? JSON.parse(this.protoText) : null;
        if (obj !== null && (typeof obj !== 'object' || Array.isArray(obj))) {
          this.protoError = this.t('json_must_be_object');
          return;
        }
        // 空对象视为恢复继承
        payload = { protocols: (obj && Object.keys(obj).length > 0) ? obj : {} };
        this.protoError = '';
      } catch (e) {
        this.protoError = this.t('json_parse_failed').replace('{msg}', e.message);
        return;
      }
    }
    try {
      await api.put(`/mailboxes/${this.protoMailbox.id}`, payload);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_proto_updated'), type: 'success' } }));
      this.closeProtoPanel();
      this.loadMailboxes();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },
};
