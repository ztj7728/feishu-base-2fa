import { bitable } from '@lark-base-open/js-sdk';
import './style.css';

// ===== 你通常只需要改这里 =====
const CONFIG = {
  // 多维表格中保存 TOTP 密钥的字段名。
  secretFieldName: '2FA Secret',

  // 可选：插件会尝试用这些字段显示“平台/名称”和“账号”。没有也没关系。
  labelFieldNames: ['网站', '平台', '名称', '服务'],
  accountFieldNames: ['账号', '邮箱', '用户名', '用户'],
};

const state = {
  secret: null,
  period: 30,
  digits: 6,
  algorithm: 'SHA-1',
  label: '',
  account: '',
  recordId: null,
  loading: false,
  lastCounter: null,
  code: '------',
};

const app = document.querySelector('#app');

app.innerHTML = `
  <main class="shell">
    <section class="card">
      <div class="eyebrow">飞书多维表格 · TOTP</div>
      <h1 id="title">2FA 验证码</h1>
      <div id="account" class="account"></div>

      <button id="codeButton" class="codeButton" type="button" aria-label="复制验证码">
        <span id="code" class="code">------</span>
        <span class="copyHint">点击复制</span>
      </button>

      <div class="timerRow">
        <div class="track"><div id="progress" class="progress"></div></div>
        <span id="seconds" class="seconds">-- 秒</span>
      </div>

      <div id="status" class="status">请选择多维表格中的一条记录</div>

      <div class="actions">
        <button id="refreshButton" class="secondary" type="button">重新读取当前行</button>
      </div>
    </section>

    <section class="help">
      <strong>表格要求</strong>
      <p>创建一个文本字段，字段名必须为 <code>${escapeHtml(CONFIG.secretFieldName)}</code>，每行放对应账号的 Base32 Secret 或完整 otpauth:// 地址。</p>
    </section>
  </main>
`;

const els = {
  title: document.querySelector('#title'),
  account: document.querySelector('#account'),
  code: document.querySelector('#code'),
  codeButton: document.querySelector('#codeButton'),
  progress: document.querySelector('#progress'),
  seconds: document.querySelector('#seconds'),
  status: document.querySelector('#status'),
  refreshButton: document.querySelector('#refreshButton'),
};

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function setStatus(message, kind = '') {
  els.status.textContent = message;
  els.status.dataset.kind = kind;
}

function normalizeAlgorithm(value) {
  const a = String(value || 'SHA1').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (a === 'SHA1') return 'SHA-1';
  if (a === 'SHA256') return 'SHA-256';
  if (a === 'SHA512') return 'SHA-512';
  throw new Error(`暂不支持算法：${value}`);
}

function parseSecretInput(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error(`字段“${CONFIG.secretFieldName}”为空`);

  if (/^otpauth:\/\//i.test(text)) {
    const url = new URL(text);
    if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp') {
      throw new Error('目前只支持 otpauth://totp/...');
    }

    const secret = url.searchParams.get('secret');
    if (!secret) throw new Error('otpauth 地址缺少 secret 参数');

    const digits = Number(url.searchParams.get('digits') || 6);
    const period = Number(url.searchParams.get('period') || 30);
    const algorithm = normalizeAlgorithm(url.searchParams.get('algorithm') || 'SHA1');

    if (![6, 7, 8].includes(digits)) throw new Error(`不支持 ${digits} 位验证码`);
    if (!Number.isFinite(period) || period <= 0 || period > 300) throw new Error('period 参数无效');

    return { secret, digits, period, algorithm };
  }

  // 裸 Base32 Secret：默认 SHA1 / 6 位 / 30 秒
  return {
    secret: text,
    digits: 6,
    period: 30,
    algorithm: 'SHA-1',
  };
}

function base32ToBytes(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(base32)
    .toUpperCase()
    .replace(/\s+/g, '')
    .replace(/=+$/g, '');

  if (!clean) throw new Error('Secret 为空');

  let bits = '';
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error(`Secret 不是有效的 Base32：发现字符 ${char}`);
    bits += value.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function counterToBytes(counter) {
  const out = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

async function generateTotp({ secret, period = 30, digits = 6, algorithm = 'SHA-1' }, nowMs = Date.now()) {
  const keyBytes = base32ToBytes(secret);
  const counter = Math.floor(nowMs / 1000 / period);

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: algorithm } },
    false,
    ['sign'],
  );

  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, counterToBytes(counter)),
  );

  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return String(binary % (10 ** digits)).padStart(digits, '0');
}

async function readFirstExistingField(table, names, recordId) {
  for (const name of names) {
    try {
      const field = await table.getFieldByName(name);
      const value = (await table.getCellString(field.id, recordId)).trim();
      if (value) return value;
    } catch {
      // 该字段不存在，继续尝试下一个名称
    }
  }
  return '';
}

async function loadCurrentRow() {
  if (state.loading) return;
  state.loading = true;
  setStatus('正在读取当前行…');

  try {
    const selection = await bitable.base.getSelection();
    const { tableId, recordId } = selection;

    if (!tableId || !recordId) {
      state.secret = null;
      state.recordId = null;
      state.code = '------';
      render();
      setStatus('请先在数据表中点击任意一行的单元格', 'warn');
      return;
    }

    const table = await bitable.base.getTableById(tableId);

    let secretField;
    try {
      secretField = await table.getFieldByName(CONFIG.secretFieldName);
    } catch {
      throw new Error(`当前数据表找不到字段“${CONFIG.secretFieldName}”`);
    }

    const rawSecret = (await table.getCellString(secretField.id, recordId)).trim();
    const parsed = parseSecretInput(rawSecret);

    const [label, account] = await Promise.all([
      readFirstExistingField(table, CONFIG.labelFieldNames, recordId),
      readFirstExistingField(table, CONFIG.accountFieldNames, recordId),
    ]);

    state.secret = parsed.secret;
    state.period = parsed.period;
    state.digits = parsed.digits;
    state.algorithm = parsed.algorithm;
    state.label = label;
    state.account = account;
    state.recordId = recordId;
    state.lastCounter = null;

    await updateCode(true);
    setStatus('已读取当前行；验证码会自动刷新', 'ok');
  } catch (error) {
    state.secret = null;
    state.code = '------';
    render();
    setStatus(error?.message || String(error), 'error');
  } finally {
    state.loading = false;
  }
}

async function updateCode(force = false) {
  if (!state.secret) {
    render();
    return;
  }

  const now = Date.now();
  const counter = Math.floor(now / 1000 / state.period);

  if (force || counter !== state.lastCounter) {
    state.code = await generateTotp({
      secret: state.secret,
      period: state.period,
      digits: state.digits,
      algorithm: state.algorithm,
    }, now);
    state.lastCounter = counter;
  }

  render(now);
}

function formatCode(code) {
  if (!code || code === '------') return code;
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function render(now = Date.now()) {
  els.title.textContent = state.label || '2FA 验证码';
  els.account.textContent = state.account || '';
  els.code.textContent = formatCode(state.code);
  els.codeButton.disabled = !state.secret || state.code === '------';

  if (!state.secret) {
    els.progress.style.width = '0%';
    els.seconds.textContent = '-- 秒';
    return;
  }

  const elapsed = (now / 1000) % state.period;
  const remaining = Math.max(0, Math.ceil(state.period - elapsed));
  const ratio = ((state.period - elapsed) / state.period) * 100;

  els.progress.style.width = `${ratio}%`;
  els.seconds.textContent = `${remaining} 秒`;
}

async function copyCode() {
  if (!state.code || state.code === '------') return;
  const plain = state.code.replace(/\s/g, '');

  try {
    await navigator.clipboard.writeText(plain);
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = plain;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
  }

  const old = els.codeButton.querySelector('.copyHint').textContent;
  els.codeButton.querySelector('.copyHint').textContent = '已复制';
  setTimeout(() => {
    els.codeButton.querySelector('.copyHint').textContent = old;
  }, 1200);
}

els.codeButton.addEventListener('click', copyCode);
els.refreshButton.addEventListener('click', loadCurrentRow);

// 点击到另一行时，自动读取新记录。
bitable.base.onSelectionChange(() => {
  window.clearTimeout(window.__totpSelectionTimer);
  window.__totpSelectionTimer = window.setTimeout(loadCurrentRow, 80);
});

// 每 250ms 更新倒计时；跨过 period 边界时只重新计算一次验证码。
setInterval(() => {
  updateCode().catch((error) => setStatus(error?.message || String(error), 'error'));
}, 250);

loadCurrentRow();
