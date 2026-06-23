window.pageMixins = window.pageMixins || {};

window.pageMixins.certs = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  certs: [],
  showAdd: false,
  newCert: { domain: '', auto_renew: true, notes: '' },
  certPollTimer: null,
  certLoading: false,
  certProgress: null,

  async loadCerts() {
    try {
      this.certs = await api.get('/certs');
    } catch (e) {
      console.error('加载证书失败', e);
    }
  },

  async addCert() {
    if (!this.newCert.domain) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_enter_domain'), type: 'error' } }));
      return;
    }
    const targetDomain = this.newCert.domain.trim();
    this.certLoading = true;
    this.certProgress = { domain: targetDomain, step: 0, total_steps: 9, step_name: '', detail: this.t('certs_applying'), done: false, error: null };
    try {
      await api.post('/certs', this.newCert);
      this.showAdd = false;
      this.newCert = { domain: '', auto_renew: true, notes: '' };
      // 开始轮询进度
      this._pollDomain = targetDomain;
      this.startCertPoll();
    } catch (e) {
      this.certLoading = false;
      this.certProgress = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async pollCertProgress() {
    try {
      const data = await api.get('/cert-progress');
      const items = data.progress || [];
      // 找到目标域名的进度
      const current = items.find(p => p.domain === this._pollDomain);
      if (current) {
        this.certProgress = {
          domain: current.domain,
          success: current.success,
          message: current.message,
          status: current.status,
          step: current.step || 0,
          total_steps: current.total_steps || 9,
          step_name: current.step_name || '',
          detail: current.detail || '',
          error: current.error,
          done: current.done,
        };
      }
      // 当目标域名完成时停止
      if (this.certProgress && this.certProgress.done) {
        this.certLoading = false;
        if (this.certPollTimer) { clearInterval(this.certPollTimer); this.certPollTimer = null; }
        if (this.certProgress.error) {
          window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.certProgress.error, type: 'error' } }));
        } else {
          window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_cert_ok'), type: 'success' } }));
        }
        this.loadCerts();
        setTimeout(() => { this.certProgress = null; this._pollDomain = null; }, 5000);
      }
    } catch (e) {
      // 轮询失败不中断
    }
  },

  startCertPoll() {
    if (this.certPollTimer) clearInterval(this.certPollTimer);
    this.certPollTimer = setInterval(() => this.pollCertProgress(), 2000);
  },

  async renewCert(id) {
    const cert = this.certs.find(c => c.id === id);
    if (!cert) return;
    const targetDomain = cert.domain;
    this.certLoading = true;
    this.certProgress = { domain: targetDomain, step: 0, total_steps: 9, step_name: '', detail: this.t('certs_applying'), done: false, error: null };
    try {
      await api.post(`/certs/${id}/renew`);
      this._pollDomain = targetDomain;
      this.startCertPoll();
    } catch (e) {
      this.certLoading = false;
      this.certProgress = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async deleteCert(id, domain) {
    if (!confirm(this.t('confirm_delete_cert').replace('{domain}', domain))) return;
    try {
      await api.delete(`/certs/${id}`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_cert_deleted'), type: 'success' } }));
      this.loadCerts();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  isExpiringSoon(expiresAt) {
    const d = new Date(expiresAt);
    const now = new Date();
    const diff = (d - now) / (1000 * 60 * 60 * 24);
    return diff < 30;
  },

  async toggleAutoRenew(id, val) {
    try {
      await api.patch(`/certs/${id}`, { auto_renew: val });
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
      this.loadCerts();
    }
  }
};
