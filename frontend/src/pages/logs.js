window.pageMixins = window.pageMixins || {};

window.pageMixins.logs = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  logs: [],
  total: 0,
  pageNum: 1,
  pageSize: 50,
  search: '',
  direction: '',
  status: '',
  hours: 24,

  async loadLogs() {
    try {
      const params = new URLSearchParams();
      if (this.search) params.append('search', this.search);
      if (this.direction) params.append('direction', this.direction);
      if (this.status) params.append('status', this.status);
      params.append('hours', this.hours);
      params.append('page', this.pageNum);
      params.append('page_size', this.pageSize);
      const data = await api.get('/logs?' + params.toString());
      this.logs = data.data || [];
      this.total = data.total || 0;
    } catch (e) {
      console.error('加载日志失败', e);
    }
  },

  async searchLogs() {
    this.pageNum = 1;
    await this.loadLogs();
  },

  async prevPage() {
    if (this.pageNum > 1) { this.pageNum--; await this.loadLogs(); }
  },

  async nextPage() {
    if (this.pageNum * this.pageSize < this.total) { this.pageNum++; await this.loadLogs(); }
  },

  directionText(d) {
    return d === 'inbound' ? this.t('queue_inbound') : this.t('queue_outbound');
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
  }
};
