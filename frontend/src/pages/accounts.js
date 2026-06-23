window.pageMixins = window.pageMixins || {};

window.pageMixins.accounts = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  users: [],
  showAdd: false,
  newUser: { username: '', password: '', role: 'admin' },
  editingId: null,
  editForm: { role: 'admin', enabled: true },

  async loadUsers() {
    try {
      this.users = await api.get('/users');
    } catch (e) {
      console.error('加载用户失败', e);
    }
  },

  async addUser() {
    try {
      await api.post('/users', this.newUser);
      this.showAdd = false;
      this.newUser = { username: '', password: '', role: 'admin' };
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_user_created'), type: 'success' } }));
      this.loadUsers();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  startEdit(u) {
    this.editingId = u.id;
    this.editForm = { role: u.role, enabled: u.enabled };
  },

  async saveEdit(id) {
    try {
      await api.put(`/users/${id}`, this.editForm);
      this.editingId = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_user_updated'), type: 'success' } }));
      this.loadUsers();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async resetPassword(id) {
    const newPass = prompt(this.t('toast_enter_password'));
    if (!newPass) return;
    try {
      await api.put(`/users/${id}`, { password: newPass });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_password_reset'), type: 'success' } }));
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  async deleteUser(id, username) {
    if (!confirm(this.t('confirm_delete_user').replace('{username}', username))) return;
    try {
      await api.delete(`/users/${id}`);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_user_deleted'), type: 'success' } }));
      this.loadUsers();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  cancelEdit() { this.editingId = null; }
};
