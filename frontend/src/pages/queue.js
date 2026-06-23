window.pageMixins = window.pageMixins || {};

window.pageMixins.queue = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  entries: [],
  stats: { pending: 0, delivering: 0, deferred: 0, total: 0 },

  async loadQueue() {
    try {
      const [queueRes, stats] = await Promise.all([
        api.get('/queue'),
        api.get('/queue/stats')
      ]);
      this.entries = queueRes.data || queueRes;
      this.stats = stats;
    } catch (e) {
      console.error('加载队列失败', e);
    }
  },

  async retryEntry(id) {
    try {
      await api.post(`/queue/${id}/retry`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_queue_retried'), type: 'success' } }));
      this.loadQueue();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async deleteEntry(id) {
    if (!confirm(this.t('confirm_delete_queue'))) return;
    try {
      await api.delete(`/queue/${id}`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_queue_deleted'), type: 'success' } }));
      this.loadQueue();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async copyError(error) {
    try {
      await navigator.clipboard.writeText(error);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_queue_copied'), type: 'success' } }));
    } catch {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = error;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_queue_copied'), type: 'success' } }));
    }
  },

  statusBadge(status) {
    const map = {
      pending: 'badge-info',
      delivering: 'badge-warning',
      deferred: 'badge-danger',
      delivered: 'badge-success',
      bounced: 'badge-danger',
    };
    return map[status] || 'badge-info';
  },

  statusText(status) {
    const map = {
      pending: this.t('queue_pending'),
      delivering: this.t('queue_delivering'),
      deferred: this.t('queue_deferred'),
      delivered: this.t('mail_delivered'),
      bounced: this.t('mail_bounced'),
    };
    return map[status] || status;
  }
};
