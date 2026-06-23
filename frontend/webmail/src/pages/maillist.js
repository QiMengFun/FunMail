import { api } from '../api.js';
import { decodeSubject, fmtDate } from '../util.js';

export function buildMailList(endpoint) {
  return {
    mails: [],
    total: 0,
    unreadCount: 0,
    pageNum: 1,
    pageSize: 20,
    search: '',
    loading: false,
    error: '',
    detailOpen: false,
    detailLoading: false,
    detail: null,
    detailError: '',
    detailTab: 'html', // 'html' | 'text'
    isDark: document.documentElement.getAttribute('data-theme') === 'dark',

    async loadMails() {
      this.loading = true;
      this.error = '';
      try {
        const params = {
          page: this.pageNum,
          page_size: this.pageSize,
          search: this.search || undefined,
        };
        const data = await api[endpoint](params);
        this.mails = data.data || data.items || data.mails || [];
        this.total = data.total || 0;
        this.unreadCount = this.mails.filter(m => !m.is_read).length;
      } catch (e) {
        console.error('[webmail] loadMails error:', e);
        this.error = e.message || (window.translations[window.getLang()] && window.translations[window.getLang()].wm_mail_load_failed || '加载失败');
      } finally {
        this.loading = false;
      }
    },

    async doSearch() {
      this.pageNum = 1;
      await this.loadMails();
    },

    async prevPage() {
      if (this.pageNum > 1) { this.pageNum--; await this.loadMails(); }
    },

    async nextPage() {
      const max = Math.max(1, Math.ceil(this.total / this.pageSize));
      if (this.pageNum < max) { this.pageNum++; await this.loadMails(); }
    },

    subject(s) { return decodeSubject(s) || ''; },

    date(iso) { return fmtDate(iso); },

    async openDetail(id) {
      this.detailOpen = true;
      this.detailLoading = true;
      this.detail = null;
      this.detailError = '';
      this.detailTab = 'html';
      try {
        this.detail = await api.detail(id);
        // 自动检测内容类型：有 HTML 优先 HTML 视图，否则切到纯文本
        const hasHtml = !!(this.detail && this.detail.body_html && this.detail.body_html.trim());
        this.detailTab = hasHtml ? 'html' : 'text';
        // 命中后把列表里对应项标记为已读
        const hit = this.mails.find((m) => m.id === id);
        if (hit && !hit.is_read) {
          hit.is_read = true;
          this.unreadCount = Math.max(0, this.unreadCount - 1);
        }
      } catch (e) {
        this.detailError = e.message || (window.translations[window.getLang()] && window.translations[window.getLang()].wm_mail_load_failed || '加载失败');
      } finally {
        this.detailLoading = false;
      }
    },

    closeDetail() {
      this.detailOpen = false;
      this.detail = null;
    },

    // 渲染 HTML 到 iframe（sandbox 防 XSS，禁 JS）
    renderHtmlIframe() {
      const html = this.detail?.body_html || '';
      if (!html) return '';
      const baseHref = window.location.origin + '/';
      const dark = this.isDark;
      const style = dark
        ? `body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0 !important;background-color:#1e293b !important;line-height:1.6;padding:12px;margin:0}body *{color:inherit}div,p,span,li,dd,dt{color:#e2e8f0 !important}img{max-width:100%}a{color:#60a5fa !important}blockquote{border-left:3px solid #475569 !important;margin:8px 0;padding:4px 12px;color:#94a3b8 !important;background:#0f172a !important}table{border-color:#334155 !important;background-color:#1e293b !important}td,th{border-color:#334155 !important;color:#e2e8f0 !important;background-color:#1e293b !important}font{color:#e2e8f0 !important}`
        : `body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;line-height:1.6;padding:12px;margin:0}img{max-width:100%}blockquote{border-left:3px solid #ddd;margin:8px 0;padding:4px 12px;color:#666;background:#f8f8f8}`;
      return `<!doctype html><html><head><meta charset="utf-8">
        <base target="_blank" href="${baseHref}">
        <style>${style}</style>
        </head><body>${html}</body></html>`;
    },

    // 构造附件下载 URL
    attachmentUrl(att) {
      if (!this.detail || att.index === undefined) return '#';
      return api.attachmentUrl(this.detail.id, att.index);
    },

    // 格式化文件大小
    formatSize(bytes) {
      if (!bytes) return '0 B';
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    },
  };
}
