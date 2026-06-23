window.pageMixins = window.pageMixins || {};

window.pageMixins.settings = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', (e) => { this.lang = e.detail.lang; });
  },
  settings: [],
  editKey: null,
  editValue: '',

  // 安全配置专用状态
  sec: {
    spam_filter_enabled: true,
    spam_threshold: 5.0,
    spam_action: 'mark',
    rbl_enabled: true,
    rbl_servers: ['zen.spamhaus.org', 'bl.spamcop.net'],
    rbl_new_server: '',
    virus_scan_enabled: false,
    virus_scan_mode: 'clamd_tcp',
    clamd_tcp_host: 'clamav',
    clamd_tcp_port: 3310,
    clamd_unix_path: '/var/run/clamav/clamd.ctl',
    virus_scan_command: 'clamdscan',
    virus_action: 'reject',
  },

  // 投递配置
  del: {
    max_retries: 3,
    retry_interval_sec: 30,
    skip_bounce_retry: true,
  },

  // SMTP 配置（邮件大小限制 + 收件人数量上限）
  smtpSize: {
    max_send_size_mb: 50,
    max_receive_size_mb: 50,
    max_recipients: 100,
    max_attachment_size_mb: 25,
  },

  // Webmail 限流配置
  rateLimit: {
    attempt_window_secs: 60,
    login_max_per_window: 5,
    register_max_per_window: 5,
    register_success_max_per_window: 1,
    block_duration_secs: 30,
  },

  // 语言配置
  langForm: {
    current: localStorage.getItem('funmail_lang') || 'zh',
  },

  // 语言选项
  languageOptions: [
    { code: 'zh', label: '中文 (简体)' },
    { code: 'en', label: 'English' },
  ],

  // 时区配置
  tz: {
    name: 'Asia/Shanghai',
    offset: '+08:00',
  },

  // 常用时区列表
  timezoneOptions: [
    { name: 'Asia/Shanghai', offset: '+08:00', label_zh: '中国标准时间 (UTC+8)', label_en: 'China Standard Time (UTC+8)' },
    { name: 'Asia/Taipei', offset: '+08:00', label_zh: '台北时间 (UTC+8)', label_en: 'Taipei Time (UTC+8)' },
    { name: 'Asia/Hong_Kong', offset: '+08:00', label_zh: '香港时间 (UTC+8)', label_en: 'Hong Kong Time (UTC+8)' },
    { name: 'Asia/Singapore', offset: '+08:00', label_zh: '新加坡时间 (UTC+8)', label_en: 'Singapore Time (UTC+8)' },
    { name: 'Asia/Tokyo', offset: '+09:00', label_zh: '日本标准时间 (UTC+9)', label_en: 'Japan Standard Time (UTC+9)' },
    { name: 'Asia/Seoul', offset: '+09:00', label_zh: '韩国标准时间 (UTC+9)', label_en: 'Korea Standard Time (UTC+9)' },
    { name: 'Asia/Kolkata', offset: '+05:30', label_zh: '印度标准时间 (UTC+5:30)', label_en: 'India Standard Time (UTC+5:30)' },
    { name: 'Asia/Dubai', offset: '+04:00', label_zh: '海湾标准时间 (UTC+4)', label_en: 'Gulf Standard Time (UTC+4)' },
    { name: 'Europe/London', offset: '+00:00', label_zh: '格林尼治时间 (UTC+0)', label_en: 'Greenwich Mean Time (UTC+0)' },
    { name: 'Europe/Paris', offset: '+01:00', label_zh: '中欧时间 (UTC+1)', label_en: 'Central European Time (UTC+1)' },
    { name: 'Europe/Berlin', offset: '+01:00', label_zh: '中欧时间 (UTC+1)', label_en: 'Central European Time (UTC+1)' },
    { name: 'Europe/Moscow', offset: '+03:00', label_zh: '莫斯科时间 (UTC+3)', label_en: 'Moscow Time (UTC+3)' },
    { name: 'America/New_York', offset: '-05:00', label_zh: '美国东部时间 (UTC-5)', label_en: 'US Eastern Time (UTC-5)' },
    { name: 'America/Chicago', offset: '-06:00', label_zh: '美国中部时间 (UTC-6)', label_en: 'US Central Time (UTC-6)' },
    { name: 'America/Denver', offset: '-07:00', label_zh: '美国山地时间 (UTC-7)', label_en: 'US Mountain Time (UTC-7)' },
    { name: 'America/Los_Angeles', offset: '-08:00', label_zh: '美国太平洋时间 (UTC-8)', label_en: 'US Pacific Time (UTC-8)' },
    { name: 'Australia/Sydney', offset: '+10:00', label_zh: '澳大利亚东部时间 (UTC+10)', label_en: 'Australia Eastern Time (UTC+10)' },
    { name: 'Pacific/Auckland', offset: '+12:00', label_zh: '新西兰时间 (UTC+12)', label_en: 'New Zealand Time (UTC+12)' },
    { name: 'UTC', offset: '+00:00', label_zh: '协调世界时 (UTC+0)', label_en: 'Coordinated Universal Time (UTC+0)' },
  ],

  get otherSettings() {
    return this.settings.filter(s => s.key !== 'security_config' && s.key !== 'delivery_config' && s.key !== 'timezone' && s.key !== 'smtp_config');
  },

  async loadSettings() {
    try {
      this.settings = await api.get('/settings');
      const secSetting = this.settings.find(s => s.key === 'security_config');
      if (secSetting && secSetting.value) {
        const v = secSetting.value;
        this.sec.spam_filter_enabled = v.spam_filter_enabled ?? true;
        this.sec.spam_threshold = v.spam_threshold ?? 5.0;
        this.sec.spam_action = v.spam_action ?? 'mark';
        this.sec.rbl_enabled = v.rbl_enabled ?? true;
        this.sec.rbl_servers = v.rbl_servers || ['zen.spamhaus.org', 'bl.spamcop.net'];
        this.sec.virus_scan_enabled = v.virus_scan_enabled ?? false;
        this.sec.virus_scan_mode = v.virus_scan_mode ?? 'clamd_tcp';
        this.sec.clamd_tcp_host = v.clamd_tcp_host ?? 'clamav';
        this.sec.clamd_tcp_port = v.clamd_tcp_port ?? 3310;
        this.sec.clamd_unix_path = v.clamd_unix_path ?? '/var/run/clamav/clamd.ctl';
        this.sec.virus_scan_command = v.virus_scan_command ?? 'clamdscan';
        this.sec.virus_action = v.virus_action ?? 'reject';
      }
      // 加载投递配置
      const delSetting = this.settings.find(s => s.key === 'delivery_config');
      if (delSetting && delSetting.value) {
        const v = delSetting.value;
        this.del.max_retries = v.max_retries ?? 3;
        this.del.retry_interval_sec = v.retry_interval_sec ?? 30;
        this.del.skip_bounce_retry = v.skip_bounce_retry ?? true;
      }
      // 加载时区配置
      const tzSetting = this.settings.find(s => s.key === 'timezone');
      if (tzSetting && tzSetting.value) {
        this.tz.name = tzSetting.value.name || 'Asia/Shanghai';
        this.tz.offset = tzSetting.value.offset || '+08:00';
      }
      // 加载 SMTP 配置
      const smtpSetting = this.settings.find(s => s.key === 'smtp_config');
      if (smtpSetting && smtpSetting.value) {
        const v = smtpSetting.value;
        const fallback = v.max_message_size_mb ?? 50;
        this.smtpSize.max_send_size_mb = v.max_send_size_mb ?? fallback;
        this.smtpSize.max_receive_size_mb = v.max_receive_size_mb ?? fallback;
        this.smtpSize.max_recipients = v.max_recipients ?? 100;
        this.smtpSize.max_attachment_size_mb = v.max_attachment_size_mb ?? 25;
      }
      // 加载 Webmail 限流配置
      const rlSetting = this.settings.find(s => s.key === 'webmail_rate_limit');
      if (rlSetting && rlSetting.value) {
        const v = rlSetting.value;
        this.rateLimit.attempt_window_secs = v.attempt_window_secs ?? 60;
        this.rateLimit.login_max_per_window = v.login_max_per_window ?? 5;
        this.rateLimit.register_max_per_window = v.register_max_per_window ?? 5;
        this.rateLimit.register_success_max_per_window = v.register_success_max_per_window ?? 1;
        this.rateLimit.block_duration_secs = v.block_duration_secs ?? 30;
      }
    } catch (e) {
      console.error('加载设置失败', e);
    }
  },

  async saveSecurityConfig() {
    try {
      const value = {
        spam_filter_enabled: this.sec.spam_filter_enabled,
        spam_threshold: parseFloat(this.sec.spam_threshold) || 5.0,
        spam_action: this.sec.spam_action,
        rbl_enabled: this.sec.rbl_enabled,
        rbl_servers: this.sec.rbl_servers.filter(s => s.trim().length > 0),
        virus_scan_enabled: this.sec.virus_scan_enabled,
        virus_scan_mode: this.sec.virus_scan_mode,
        clamd_tcp_host: this.sec.clamd_tcp_host || 'clamav',
        clamd_tcp_port: parseInt(this.sec.clamd_tcp_port) || 3310,
        clamd_unix_path: this.sec.clamd_unix_path || '/var/run/clamav/clamd.ctl',
        virus_scan_command: this.sec.virus_scan_command || 'clamdscan',
        virus_action: this.sec.virus_action,
      };
      await api.put('/settings/security_config', { key: 'security_config', value });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_security_saved'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // RBL 标签操作
  addRblServer() {
    const s = this.sec.rbl_new_server.trim();
    if (s && !this.sec.rbl_servers.includes(s)) {
      this.sec.rbl_servers.push(s);
    }
    this.sec.rbl_new_server = '';
  },
  removeRblServer(idx) {
    this.sec.rbl_servers.splice(idx, 1);
  },

  // 投递配置保存
  async saveDeliveryConfig() {
    try {
      const value = {
        max_retries: parseInt(this.del.max_retries) || 3,
        retry_interval_sec: parseInt(this.del.retry_interval_sec) || 30,
        skip_bounce_retry: this.del.skip_bounce_retry,
      };
      await api.put('/settings/delivery_config', { key: 'delivery_config', value });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_delivery_saved'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // SMTP 邮件大小限制保存（合并已有 smtp_config，避免覆盖其他字段）
  async saveSmtpSizeConfig() {
    try {
      const send = parseInt(this.smtpSize.max_send_size_mb) || 50;
      const recv = parseInt(this.smtpSize.max_receive_size_mb) || 50;
      if (send < 1 || recv < 1) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('settings_mail_size_invalid'), type: 'error' } }));
        return;
      }
      // 读取当前 smtp_config 与新值合并
      const existing = (this.settings.find(s => s.key === 'smtp_config') || {}).value || {};
      const value = {
        ...existing,
        max_send_size_mb: send,
        max_receive_size_mb: recv,
        max_recipients: parseInt(this.smtpSize.max_recipients) || 100,
        max_attachment_size_mb: parseInt(this.smtpSize.max_attachment_size_mb) || 25,
        // 兼容旧字段：取较大值，避免老服务读到不一致
        max_message_size_mb: Math.max(send, recv),
      };
      await api.put('/settings/smtp_config', { key: 'smtp_config', value });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_settings_saved'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // Webmail 限流配置保存
  async saveRateLimitConfig() {
    try {
      const value = {
        attempt_window_secs: parseInt(this.rateLimit.attempt_window_secs) || 60,
        login_max_per_window: parseInt(this.rateLimit.login_max_per_window) || 5,
        register_max_per_window: parseInt(this.rateLimit.register_max_per_window) || 5,
        register_success_max_per_window: parseInt(this.rateLimit.register_success_max_per_window) || 1,
        block_duration_secs: parseInt(this.rateLimit.block_duration_secs) || 30,
      };
      await api.put('/settings/webmail_rate_limit', { key: 'webmail_rate_limit', value });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_settings_saved'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // 时区选择变更
  onTimezoneChange() {
    const opt = this.timezoneOptions.find(o => o.name === this.tz.name);
    if (opt) {
      this.tz.offset = opt.offset;
    }
  },

  // 时区配置保存
  async saveTimezoneConfig() {
    try {
      const value = {
        name: this.tz.name,
        offset: this.tz.offset,
      };
      await api.put('/settings/timezone', { key: 'timezone', value });
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: t('success'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  // 语言配置保存
  async saveLanguageConfig() {
    try {
      const value = this.langForm.current;
      await api.put('/settings/language', { key: 'language', value });
      setLang(value);
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: t('success'), type: 'success' } }));
      window.dispatchEvent(new CustomEvent('lang-changed', { detail: { lang: value } }));
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  startEdit(s) {
    this.editKey = s.key;
    this.editValue = typeof s.value === 'string' ? s.value : JSON.stringify(s.value, null, 2);
  },

  async saveSetting(key) {
    try {
      let value;
      try { value = JSON.parse(this.editValue); } catch { value = this.editValue; }
      await api.put(`/settings/${key}`, { key, value });
      this.editKey = null;
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: this.t('toast_settings_saved'), type: 'success' } }));
      this.loadSettings();
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { msg: e.message, type: 'error' } }));
    }
  },

  cancelEdit() { this.editKey = null; },

  tzLabel(opt) {
    return this.lang === 'zh' ? opt.label_zh : opt.label_en;
  },

  formatValue(v) {
    if (typeof v === 'object') return JSON.stringify(v, null, 2);
    return String(v);
  },

  settingLabel(key) {
    const labels = {
      smtp_config: this.t('settings_delivery') + ' - SMTP',
      pop3_config: this.t('settings_delivery') + ' - POP3',
      imap_config: this.t('settings_delivery') + ' - IMAP',
      delivery_config: this.t('settings_delivery_title'),
      jwt_secret: 'JWT ' + this.t('password'),
      notification_config: this.t('settings_title'),
      timezone: this.t('settings_timezone'),
    };
    return labels[key] || key;
  }
};
