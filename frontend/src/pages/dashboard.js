window.pageMixins = window.pageMixins || {};

function isDark() { return document.documentElement.classList.contains('dark'); }
function chartColors() {
  const d = isDark();
  return {
    axisLine: d ? 'rgb(57,57,57)' : '#e5e7eb',
    splitLine: d ? 'rgb(50,50,50)' : '#f3f4f6',
    axisLabel: d ? 'rgb(160,160,160)' : '#9ca3af',
    tooltipBg: d ? 'rgb(39,39,39)' : 'rgba(255,255,255,0.95)',
    tooltipBorder: d ? 'rgb(57,57,57)' : '#e5e7eb',
    tooltipText: d ? 'rgb(230,230,230)' : '#374151',
    legendText: d ? 'rgb(160,160,160)' : '#6b7280',
  };
}

window.pageMixins.dashboard = {
  t(key) { return (window.translations[this.lang] && window.translations[this.lang][key]) || key; },
  lang: getLang(),
  init() {
    window.addEventListener('lang-changed', () => {
      this.lang = getLang();
      this.renderTrafficChart();
      this.renderTraffic30dChart();
      this.renderQueueChart();
    });
  },
  stats: { total_inbound: 0, total_outbound: 0, total_blocked: 0, total_spam: 0, total_bounced: 0, active_domains: 0, active_mailboxes: 0, queue_pending: 0, queue_deferred: 0, avg_latency_ms: 0 },
  trafficData: { hours: [], inbound: [], outbound: [] },
  traffic30dData: { days: [], inbound: [], outbound: [], bounced: [] },
  trafficChart: null,
  traffic30dChart: null,
  queueChart: null,

  async loadDashboard() {
    try {
      const data = await api.get('/stats/dashboard');
      this.stats = { ...this.stats, ...data };
    } catch (e) {
      console.error('加载仪表盘失败', e);
    }
    try {
      const data = await api.get('/stats/traffic');
      this.trafficData = data;
    } catch (e) {
      console.error('加载趋势数据失败', e);
    }
    try {
      const data = await api.get('/stats/traffic7d');
      this.traffic30dData = data;
    } catch (e) {
      console.error('加载7天趋势数据失败', e);
    }
    this.renderTrafficChart();
    this.renderTraffic30dChart();
    this.renderQueueChart();
  },

  renderTrafficChart() {
    const dom = document.getElementById('traffic-chart');
    if (!dom || typeof echarts === 'undefined') return;
    this.trafficChart = echarts.getInstanceByDom(dom) || echarts.init(dom);
    const hours = this.trafficData.hours.length > 0 ? this.trafficData.hours : ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23'];
    const inbound = this.trafficData.inbound.length > 0 ? this.trafficData.inbound : Array(24).fill(0);
    const outbound = this.trafficData.outbound.length > 0 ? this.trafficData.outbound : Array(24).fill(0);
    this.trafficChart.setOption({
      tooltip: { trigger: 'axis', appendTo: 'body', backgroundColor: chartColors().tooltipBg, borderColor: chartColors().tooltipBorder, textStyle: { color: chartColors().tooltipText, fontSize: 12 } },
      legend: { data: [this.t('queue_inbound'), this.t('queue_outbound')], top: 0, textStyle: { color: chartColors().legendText, fontSize: 11 }, itemWidth: 12, itemHeight: 8 },
      grid: { left: 45, right: 10, top: 35, bottom: 25 },
      xAxis: { type: 'category', data: hours, axisLine: { lineStyle: { color: chartColors().axisLine } }, axisLabel: { color: chartColors().axisLabel, fontSize: 10 }, axisTick: { show: false }, boundaryGap: false },
      yAxis: { type: 'value', splitLine: { lineStyle: { color: chartColors().splitLine, type: 'dashed' } }, axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: chartColors().axisLabel, fontSize: 10 } },
      series: [
        { name: this.t('queue_inbound'), type: 'line', smooth: true, symbol: 'circle', symbolSize: 4, lineStyle: { width: 2, color: '#3b82f6' }, itemStyle: { color: '#3b82f6' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(59,130,246,0.25)' }, { offset: 1, color: 'rgba(59,130,246,0.02)' }]) }, data: inbound },
        { name: this.t('queue_outbound'), type: 'line', smooth: true, symbol: 'circle', symbolSize: 4, lineStyle: { width: 2, color: '#f59e0b' }, itemStyle: { color: '#f59e0b' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(245,158,11,0.2)' }, { offset: 1, color: 'rgba(245,158,11,0.02)' }]) }, data: outbound }
      ]
    }, true);
  },

  renderTraffic30dChart() {
    const dom = document.getElementById('traffic30d-chart');
    if (!dom || typeof echarts === 'undefined') return;
    this.traffic30dChart = echarts.getInstanceByDom(dom) || echarts.init(dom);
    const days = this.traffic30dData.days.length > 0 ? this.traffic30dData.days : Array.from({length: 30}, (_, i) => { const d = new Date(); d.setDate(d.getDate() - 29 + i); return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0'); });
    const inbound = this.traffic30dData.inbound.length > 0 ? this.traffic30dData.inbound : Array(30).fill(0);
    const outbound = this.traffic30dData.outbound.length > 0 ? this.traffic30dData.outbound : Array(30).fill(0);
    const bounced = this.traffic30dData.bounced.length > 0 ? this.traffic30dData.bounced : Array(30).fill(0);
    this.traffic30dChart.setOption({
      tooltip: { trigger: 'axis', appendTo: 'body', backgroundColor: chartColors().tooltipBg, borderColor: chartColors().tooltipBorder, textStyle: { color: chartColors().tooltipText, fontSize: 12 } },
      legend: { data: [this.t('queue_inbound'), this.t('queue_outbound'), this.t('mail_bounced')], top: 0, textStyle: { color: chartColors().legendText, fontSize: 11 }, itemWidth: 12, itemHeight: 8 },
      grid: { left: 45, right: 10, top: 35, bottom: 25 },
      xAxis: { type: 'category', data: days, axisLine: { lineStyle: { color: chartColors().axisLine } }, axisLabel: { color: chartColors().axisLabel, fontSize: 10, interval: 4 }, axisTick: { show: false }, boundaryGap: false },
      yAxis: { type: 'value', splitLine: { lineStyle: { color: chartColors().splitLine, type: 'dashed' } }, axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: chartColors().axisLabel, fontSize: 10 } },
      series: [
        { name: this.t('queue_inbound'), type: 'line', smooth: true, symbol: 'circle', symbolSize: 4, lineStyle: { width: 2, color: '#3b82f6' }, itemStyle: { color: '#3b82f6' }, data: inbound },
        { name: this.t('queue_outbound'), type: 'line', smooth: true, symbol: 'circle', symbolSize: 4, lineStyle: { width: 2, color: '#f59e0b' }, itemStyle: { color: '#f59e0b' }, data: outbound },
        { name: this.t('mail_bounced'), type: 'line', smooth: true, symbol: 'circle', symbolSize: 4, lineStyle: { width: 2, color: '#ef4444' }, itemStyle: { color: '#ef4444' }, data: bounced }
      ]
    }, true);
  },

  renderQueueChart() {
    const dom = document.getElementById('queue-chart');
    if (!dom || typeof echarts === 'undefined') return;
    this.queueChart = echarts.getInstanceByDom(dom) || echarts.init(dom);
    this.queueChart.setOption({
      tooltip: { trigger: 'item', appendTo: 'body', backgroundColor: chartColors().tooltipBg, borderColor: chartColors().tooltipBorder, textStyle: { color: chartColors().tooltipText, fontSize: 12 } },
      legend: { top: 0, textStyle: { color: chartColors().legendText, fontSize: 11 }, itemWidth: 12, itemHeight: 8 },
      series: [{
        type: 'pie', radius: ['45%', '70%'], center: ['50%', '55%'],
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
        data: [
          { value: this.stats.queue_pending || 0, name: this.t('queue_pending'), itemStyle: { color: '#3b82f6' } },
          { value: this.stats.queue_deferred || 0, name: this.t('queue_deferred'), itemStyle: { color: '#f59e0b' } },
        ]
      }]
    }, true);
  },

  refreshAllCharts() {
    this.loadDashboard();
    requestAnimationFrame(() => {
      [this.trafficChart, this.traffic30dChart, this.queueChart].forEach(c => {
        if (c && !c.isDisposed()) { c.resize(); }
      });
    });
  },

  resizeCharts() {
    requestAnimationFrame(() => {
      [this.trafficChart, this.traffic30dChart, this.queueChart].forEach(c => {
        if (c && !c.isDisposed()) { c.resize(); }
      });
    });
  },

  destroy() {
    [this.trafficChart, this.traffic30dChart, this.queueChart].forEach(c => { if (c) { c.dispose(); } });
    this.trafficChart = null;
    this.traffic30dChart = null;
    this.queueChart = null;
  }
};
