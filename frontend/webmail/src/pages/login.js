import { api, saveToken } from '../api.js';

export const loginPage = () => ({
  email: '',
  password: '',
  loading: false,
  error: '',
  showPwd: false,
  registerEnabled: false,
  showRegister: false,
  regEmail: '',
  regPassword: '',
  regConfirm: '',
  regLoading: false,
  regError: '',
  regSuccess: '',
  // 验证码
  captchaId: '',
  captchaQuestion: '',
  captchaAnswer: '',

  async init() {
    await this.checkRegister();
  },

  async checkRegister() {
    try {
      // 从当前访问的 hostname 提取域名
      const host = window.location.hostname;
      // 如果是 mail.domain.com 格式，取 domain.com
      const parts = host.split('.');
      const domain = parts.length > 2 ? parts.slice(1).join('.') : host;
      const res = await fetch('/api/webmail/register-info?domain=' + encodeURIComponent(domain));
      if (res.ok) {
        const data = await res.json();
        this.registerEnabled = !!data.enabled;
      }
    } catch {}
  },

  // 获取验证码
  async loadCaptcha() {
    try {
      const res = await fetch('/api/webmail/captcha');
      const data = await res.json();
      this.captchaId = data.captcha_id;
      this.captchaQuestion = data.question;
      this.captchaAnswer = '';
    } catch {}
  },

  // 打开注册面板时加载验证码
  async toggleRegister() {
    this.showRegister = !this.showRegister;
    this.regError = '';
    this.regSuccess = '';
    if (this.showRegister) {
      if (this.email) this.regEmail = this.email;
      await this.loadCaptcha();
    }
  },

  async submit() {
    this.error = '';
    if (!this.email || !this.password) {
      this.error = this.t('wm_login_error_empty');
      return;
    }
    this.loading = true;
    try {
      const res = await api.login(this.email.trim(), this.password);
      saveToken(res.token);
      window.dispatchEvent(new CustomEvent('webmail-login'));
    } catch (e) {
      this.error = e.message || this.t('wm_login_error_failed');
    } finally {
      this.loading = false;
    }
  },

  async submitRegister() {
    this.regError = '';
    this.regSuccess = '';
    if (!this.regEmail || !this.regPassword) {
      this.regError = this.t('wm_register_error_empty');
      return;
    }
    if (this.regPassword.length < 8) {
      this.regError = this.t('wm_register_error_password_length');
      return;
    }
    if (this.regPassword !== this.regConfirm) {
      this.regError = this.t('wm_register_error_password_mismatch');
      return;
    }
    // 解析邮箱：user@domain
    const atIdx = this.regEmail.trim().lastIndexOf('@');
    if (atIdx < 0) {
      this.regError = this.t('wm_register_error_email_invalid') || '邮箱格式错误';
      return;
    }
    const username = this.regEmail.trim().substring(0, atIdx).toLowerCase();
    const domain = this.regEmail.trim().substring(atIdx + 1).toLowerCase();
    if (!username || !domain) {
      this.regError = this.t('wm_register_error_email_invalid') || '邮箱格式错误';
      return;
    }
    // 验证码
    if (!this.captchaAnswer) {
      this.regError = this.t('wm_register_error_captcha_empty') || '请输入验证码';
      return;
    }
    this.regLoading = true;
    try {
      const res = await fetch('/api/webmail/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain,
          username: username,
          password: this.regPassword,
          captcha_id: this.captchaId,
          captcha_answer: parseInt(this.captchaAnswer, 10),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        this.regError = data.error || this.t('wm_register_error_failed');
        // 验证码已失效，重新加载
        await this.loadCaptcha();
        return;
      }
      this.regSuccess = this.t('wm_register_success');
      this.regEmail = '';
      this.regPassword = '';
      this.regConfirm = '';
      this.captchaAnswer = '';
    } catch (e) {
      this.regError = this.t('wm_register_error_failed');
      await this.loadCaptcha();
    } finally {
      this.regLoading = false;
    }
  },
});
