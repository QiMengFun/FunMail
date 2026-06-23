window.pageMixins = window.pageMixins || {};

window.pageMixins.domains = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  domains: [],
  showAdd: false,
  newDomain: { name: '', default_quota_mb: 1024, notes: '' },
  editingId: null,
  editForm: { enabled: true, default_quota_mb: 1024, notes: '' },
  // 注册配置侧边栏
  showRegisterPanel: false,
  registerDomain: null,            // 当前正在编辑 register_config 的 domain
  registerConfigText: '',          // JSON 文本（textarea）
  registerConfigError: '',         // JSON 解析错误
  registerConfigTab: 'form',       // 'form' | 'json'

  // DNS 设置向导
  showWizard: false,
  wizardDomain: null,
  wizardStep: 1,  // 1=DNS记录 2=验证DNS 3=申请证书 4=完成
  dnsRecords: [],
  serverIp: '',
  verifying: false,
  allVerified: false,
  certLoading: false,
  certResults: [],
  certMethod: 'acme',       // 'acme' | 'self-signed'
  guideLoading: false, // DNS引导数据加载状态

  async loadDomains() {
    try {
      this.domains = await api.get('/domains');
    } catch (e) {
      console.error('加载域名失败', e);
    }
  },

  async addDomain() {
    try {
      const result = await api.post('/domains', this.newDomain);
      this.showAdd = false;
      this.newDomain = { name: '', default_quota_mb: 1024, notes: '' };
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_domain_created'), type: 'success' } }));
      await this.loadDomains();
      // 自动打开设置向导
      this.openWizard(result.id);
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  startEdit(d) {
    this.editingId = d.id;
    this.editForm = { enabled: d.enabled, default_quota_mb: d.default_quota_mb, notes: d.notes || '' };
  },

  async saveEdit(id) {
    try {
      await api.put(`/domains/${id}`, this.editForm);
      this.editingId = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_domain_updated'), type: 'success' } }));
      this.loadDomains();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // ============ 注册配置侧边栏 ============

  /// 打开侧边栏，加载该域名的 register_config
  openRegisterPanel(d) {
    this.registerDomain = d;
    this.registerConfigText = JSON.stringify(d.register_config || {}, null, 2);
    this.registerConfigError = '';
    this.registerConfigTab = 'form';
    this.initCfgForm();
    this.showRegisterPanel = true;
  },

  closeRegisterPanel() {
    this.showRegisterPanel = false;
    this.registerDomain = null;
    this.registerConfigText = '';
    this.registerConfigError = '';
  },

  /// 从 JSON 文本解析同步到 form 字段
  syncConfigFromText() {
    try {
      const obj = JSON.parse(this.registerConfigText || '{}');
      this.registerConfigError = '';
      return obj;
    } catch (e) {
      this.registerConfigError = this.t('json_parse_failed').replace('{msg}', e.message);
      return null;
    }
  },

  /// 表单 → JSON 文本
  syncConfigFromForm() {
    // 读取所有绑定到 registerConfig.* 的字段，构造 JSON
    const obj = JSON.parse(this.registerConfigText || '{}');
    // 这里的字段从 form input 拿
    if (this._cfgForm) {
      obj.enabled = !!this._cfgForm.enabled;
      obj.default_quota_mb = parseInt(this._cfgForm.default_quota_mb) || 0;
      obj.allow_smtp = !!this._cfgForm.allow_smtp;
      obj.allow_pop3 = !!this._cfgForm.allow_pop3;
      obj.allow_imap = !!this._cfgForm.allow_imap;
      obj.allow_forward = !!this._cfgForm.allow_forward;
      obj.max_aliases = parseInt(this._cfgForm.max_aliases) || 0;
      obj.max_forwarders = parseInt(this._cfgForm.max_forwarders) || 0;
      obj.max_mail_per_day = parseInt(this._cfgForm.max_mail_per_day) || 0;
      obj.captcha_required = !!this._cfgForm.captcha_required;
      // 邮件大小覆盖（留空字符串 → 删除该键，继承全局）
      const sendMb = (this._cfgForm.max_send_size_mb || '').toString().trim();
      const recvMb = (this._cfgForm.max_receive_size_mb || '').toString().trim();
      if (sendMb === '') { delete obj.max_send_size_mb; }
      else { obj.max_send_size_mb = parseInt(sendMb) || 0; }
      if (recvMb === '') { delete obj.max_receive_size_mb; }
      else { obj.max_receive_size_mb = parseInt(recvMb) || 0; }
    }
    this.registerConfigText = JSON.stringify(obj, null, 2);
    return obj;
  },

  initCfgForm() {
    try {
      const obj = JSON.parse(this.registerConfigText || '{}');
      this._cfgForm = {
        enabled: obj.enabled ?? false,
        default_quota_mb: obj.default_quota_mb ?? 1024,
        allow_smtp: obj.allow_smtp ?? true,
        allow_pop3: obj.allow_pop3 ?? true,
        allow_imap: obj.allow_imap ?? true,
        allow_forward: obj.allow_forward ?? false,
        max_aliases: obj.max_aliases ?? 1,
        max_forwarders: obj.max_forwarders ?? 1,
        max_mail_per_day: obj.max_mail_per_day ?? 100,
        captcha_required: obj.captcha_required ?? true,
        max_send_size_mb: obj.max_send_size_mb ?? '',
        max_receive_size_mb: obj.max_receive_size_mb ?? '',
      };
    } catch {
      this._cfgForm = {
        enabled: false, default_quota_mb: 1024, allow_smtp: true, allow_pop3: true, allow_imap: true,
        allow_forward: false, max_aliases: 1, max_forwarders: 1, max_mail_per_day: 100,
        captcha_required: true,
        max_send_size_mb: '', max_receive_size_mb: '',
      };
    }
  },

  async saveRegisterConfig() {
    if (!this.registerDomain) return;
    let cfg;
    if (this.registerConfigTab === 'form') {
      cfg = this.syncConfigFromForm();
    } else {
      cfg = this.syncConfigFromText();
      if (!cfg) return; // JSON 解析失败
    }
    try {
      await api.put(`/domains/${this.registerDomain.id}`, { register_config: cfg });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_register_updated'), type: 'success' } }));
      this.closeRegisterPanel();
      this.loadDomains();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  /// 当前 register_config 是否允许注册
  isRegisterEnabled(d) {
    return !!(d.register_config && d.register_config.enabled);
  },

  /// 该域名的注册配置摘要（用于列表展示）
  registerSummary(d) {
    const c = d.register_config || {};
    if (!c.enabled) return this.t('register_summary_off');
    const protocols = [];
    if (c.allow_smtp) protocols.push('SMTP');
    if (c.allow_pop3) protocols.push('POP3');
    if (c.allow_imap) protocols.push('IMAP');
    const protoStr = protocols.length ? protocols.join('/') : this.t('register_summary_no_proto');
    return `${c.default_quota_mb || 1024}MB · ${protoStr}`;
  },

  async deleteDomain(id, name) {
    if (!confirm(this.t('confirm_delete_domain').replace('{name}', name))) return;
    try {
      await api.delete(`/domains/${id}`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_domain_deleted'), type: 'success' } }));
      this.loadDomains();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  cancelEdit() { this.editingId = null; },

  // ============ DNS 设置向导 ============

  async openWizard(domainId) {
    const d = this.domains.find(x => x.id === domainId);
    if (!d) return;
    this.wizardDomain = d;
    this.wizardStep = 1;
    this.certMethod = 'acme';
    this.allVerified = false;
    this.certResults = [];
    this.guideLoading = true;
    this.showWizard = true;
    await this.loadDnsGuide(domainId);
  },

  async loadDnsGuide(domainId) {
    this.guideLoading = true;
    try {
      const data = await api.get(`/domains/${domainId}/dns-guide`);
      this.dnsRecords = data.records;
      this.serverIp = data.server_ip;
      this.allVerified = data.all_verified || false;
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_dns_load_failed').replace('{msg}', e.message), type: 'error' } }));
    } finally {
      this.guideLoading = false;
    }
  },

  async verifyDns() {
    if (!this.wizardDomain) return;
    this.verifying = true;
    try {
      const data = await api.post(`/domains/${this.wizardDomain.id}/verify-dns`);
      this.dnsRecords = data.records;
      this.allVerified = data.all_verified;
      if (data.all_verified) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_dns_all_verified'), type: 'success' } }));
        this.wizardStep = 3;
      } else {
        const verified = data.records.filter(r => r.verified).length;
        const total = data.records.length;
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_dns_partial_verified').replace('{verified}', verified).replace('{total}', total), type: 'warning' } }));
      }
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_dns_verify_failed').replace('{msg}', e.message), type: 'error' } }));
    } finally {
      this.verifying = false;
    }
  },

  certPollTimer: null,

  async setupCert() {
    if (!this.wizardDomain) return;
    this.certLoading = true;
    this.certResults = [];
    try {
      const res = await api.post(`/domains/${this.wizardDomain.id}/setup-cert`, { method: this.certMethod });
      // 自签名证书是同步返回的
      if (res.method === 'self-signed') {
        this.certLoading = false;
        this.wizardStep = 4;
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_self_signed_ok'), type: 'success' } }));
        await this.loadDomains();
        this.wizardDomain = this.domains.find(x => x.id === this.wizardDomain.id);
        return;
      }
      // ACME 证书：开始轮询进度
      this.startCertPoll();
    } catch (e) {
      this.certLoading = false;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_cert_apply_failed').replace('{msg}', e.message), type: 'error' } }));
    }
  },

  async pollCertProgress() {
    try {
      const data = await api.get('/cert-progress');
      this.certResults = (data.progress || []).map(p => ({
        domain: p.domain,
        success: p.success,
        message: p.message,
        status: p.status,
        step: p.step || 0,
        total_steps: p.total_steps || 9,
        step_name: p.step_name || '',
        detail: p.detail || '',
        error: p.error,
      }));
      if (data.all_done) {
        this.certLoading = false;
        if (this.certPollTimer) { clearInterval(this.certPollTimer); this.certPollTimer = null; }
        if (data.all_success) {
          this.wizardStep = 4;
          window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_cert_all_ok'), type: 'success' } }));
        } else {
          window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_cert_partial'), type: 'warning' } }));
        }
        await this.loadDomains();
        this.wizardDomain = this.domains.find(x => x.id === this.wizardDomain.id);
      }
    } catch (e) {
      // 轮询失败不中断
    }
  },

  startCertPoll() {
    if (this.certPollTimer) clearInterval(this.certPollTimer);
    this.certPollTimer = setInterval(() => this.pollCertProgress(), 2000);
  },

  closeWizard() {
    if (this.certPollTimer) { clearInterval(this.certPollTimer); this.certPollTimer = null; }
    this.showWizard = false;
    this.wizardDomain = null;
    this.certLoading = false;
    this.loadDomains();
  },

  copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_copied'), type: 'success' } }));
      });
    } else {
      // HTTP 降级方案：使用隐藏 textarea
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_copied'), type: 'success' } }));
      } catch (e) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_copy_failed'), type: 'error' } }));
      }
      document.body.removeChild(ta);
    }
  },

  getSetupStatus(d) {
    if (d.setup_completed) return 'completed';
    if (d.mx_verified || d.spf_verified || d.dkim_verified || d.dmarc_verified) return 'partial';
    return 'pending';
  },

  getSetupStatusText(d) {
    const s = this.getSetupStatus(d);
    if (s === 'completed') return this.t('setup_status_completed');
    if (s === 'partial') return this.t('setup_status_partial');
    return this.t('setup_status_pending');
  }
};
