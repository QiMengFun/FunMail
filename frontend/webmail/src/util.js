// 与 admin/mail.js 中 decodeSubject 等价的工具函数，重复独立，避免跨子域引用

/**
 * 解析 RFC 2047 Encoded-Word
 *   =?charset?B?base64?=
 *   =?charset?Q?quoted-printable?=
 */
export function decodeSubject(input) {
  if (!input) return '';
  const s = String(input);
  // 处理组合（一个字段可能多个 encoded-word）
  return s.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g,
    (_m, charset, enc, body) => {
      try {
        let bytes;
        if (enc === 'B' || enc === 'b') {
          // base64
          const bin = atob(body.replace(/\s+/g, ''));
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        } else {
          // Q encoding: _ → space, =XX → byte
          const replaced = body.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16)));
          bytes = new Uint8Array(replaced.length);
          for (let i = 0; i < replaced.length; i++) bytes[i] = replaced.charCodeAt(i) & 0xff;
        }
        // 把 gb2312 / gbk 映射到 gbk
        let c = charset.toLowerCase();
        if (c === 'gb2312') c = 'gbk';
        return new TextDecoder(c).decode(bytes);
      } catch {
        return body;
      }
    }
  );
}

export function fmtDate(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    if (sameDay) {
      return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }
    const sameYear = d.getFullYear() === now.getFullYear();
    return sameYear
      ? d.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' })
      : d.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });
  } catch { return iso; }
}

export function fmtFullDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false });
  } catch { return iso; }
}

export function fmtSize(n) {
  if (!n && n !== 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

export function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
