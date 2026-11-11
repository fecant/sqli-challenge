/**
 * 神的sql网站 · 四级注入阶梯（对标 CTF 赛题设计）
 *
 * 设计原则：每一关只叠一种"真实赛题里会出现的约束"，且每一关都可解。
 *
 *   L1 无过滤 + 全回显        → 字符串闭合、注释
 *   L2 单次删词 + 全回显      → 双写绕过、数列、sqlite_master 查表
 *   L3 递归删词 + 去空格 + 无回显 → 双写失效、用注释符当空格、布尔盲注
 *   L4 同 L3 过滤 + 三态同一响应  → 只有时间差可用：sleep() + AND 短路
 *
 * 与 PHP 版的差异（为了能安全公网分享）：内存 SQLite、无文件系统、无出站、
 * 单语句执行、每 30 分钟重播种、输出做 HTML 转义。
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

/* ------------------------------------------------------------------ *
 * 四关的 flag：各自独立，互不泄露
 * 每一关有独立的库实例，所以 L2 拖库拖不到 L3/L4 的 flag
 * ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ *
 * 运行模式
 *   LEVEL=1..4  → 单关卡模式（CTF 平台动态题：一个容器 = 一道题 = 一个 flag）
 *   不设 LEVEL  → 四关全开（本地自用 / 现有分享链接）
 *   ENABLE_ADMIN=1/0 → 管理接口（/stats /export /reset /addscore）开关
 *                      单关卡容器默认关，全关模式默认开，可用此变量强制覆盖
 * ------------------------------------------------------------------ */
const SINGLE = (() => {
  const n = parseInt(process.env.LEVEL || '0', 10);
  return n >= 1 && n <= 4 ? n : 0;
})();
// 管理接口开关：单关卡容器默认关（别把后门递给选手），全关模式默认开（线上自用那套）
// 显式设 ENABLE_ADMIN=1/0 可强制覆盖
const ADMIN_ON = process.env.ENABLE_ADMIN !== undefined
  ? process.env.ENABLE_ADMIN === '1'
  : !SINGLE;

// 动态 flag：平台注入的环境变量优先；都没给则回落到默认值（本地调试用）
const INJECTED_FLAG = process.env.CTF_FLAG || process.env.GZCTF_FLAG || process.env.FLAG
  || process.env.DASCTF_FLAG || process.env.CTF_PLUS_FLAG || process.env.CHALLENGE_FLAG
  || process.env.FLAG_1 || process.env.FLAG_2 || process.env.FLAG_3 || process.env.FLAG_4 || '';

const FLAGS = {
  1: 'flag{l1_c0mm3nt_byp4ss}',
  2: 'flag{l2_d0ubl3_wr1t3_un10n}',
  3: 'flag{l3_r3curs1v3_bl1nd}',
  4: 'flag{l4_s1l3nc3_0r4cl3}',
};
if (SINGLE && INJECTED_FLAG) FLAGS[SINGLE] = INJECTED_FLAG;

const PUBLIC_ROWS = [
  ['admin', 'admin123'],
  ['cl4y', 'i_want_to_play_2077'],
  ['sql', 'sql_injection_is_so_fun'],
  ['porn', 'do_you_know_pornhub'],
  ['git', 'github_is_different_from_pornhub'],
  ['Stop', 'you_found_flag_so_stop'],
  ['badguy', 'i_told_you_to_stop'],
  ['hacker', 'hack_by_cl4y'],
];

/* ------------------------------------------------------------------ *
 * 关卡定义
 *   echo: full → 回显第 2/3 列；none → 只区分成功/失败；silent → 三态完全同页
 *   filter: none | single(删一次) | recursive(删到删不动 + 去空格)
 * ------------------------------------------------------------------ */
const LEVELS = {
  1: {
    id: 1, accent: '#34D399', diff: 'EASY',
    name: '第一关 · 深渊回望',
    sub: '哼、就这？连引号都不敢闭合的话，本小姐可要笑你一辈子了哦～',
    tech: 'no filter · full echo',
    echo: 'full', filter: 'none', quips: 'tutorial',
  },
  2: {
    id: 2, accent: '#22D3EE', diff: 'MEDIUM',
    name: '第二关 · 偶像的黄昏',
    sub: '诶——双写都不会？笨蛋笨蛋，人家可、可没有在提示你哦！',
    tech: 'single-pass strip · full echo',
    echo: 'full', filter: 'single', quips: 'tutorial',
  },
  3: {
    id: 3, accent: '#FBBF24', diff: 'HARD',
    name: '第三关 · 永恒轮回',
    sub: '看不见了吧？嘻嘻，活该～ 谁让你只会照抄别人的 writeup 呢。',
    tech: 'recursive strip · no space · no echo',
    echo: 'none', filter: 'recursive', quips: 'taunt',
  },
  4: {
    id: 4, accent: '#F87171', diff: 'INSANE',
    name: '第四关 · 上帝已死',
    sub: '……不、不理你了。反正你也猜不到的啦，哼。',
    tech: 'recursive strip · no space · silent response',
    echo: 'silent', filter: 'recursive', quips: 'none',
  },
};

/* ------------------------------------------------------------------ *
 * 故事线：通关一关放一章。前三章是前传，第四章是他们给的结局 + 尾声
 * ------------------------------------------------------------------ */
const STORY = {
  1: {
    t: '城门',
    body: '从前有个勇者，走了很远的路，站在城堡门口。门上写着：欢迎光临。他不信。他在门口站了三天，等一个陷阱。第四天他推了一下门，门开了——没有锁，从来就没有锁。他忽然明白：他等了三天的，不是敌人，是自己敢不敢伸手。深渊在门后看着他；而他也终于，开始看着深渊',
  },
  2: {
    t: '地图',
    body: '勇者在地窖里找到一张地图。地图上画着宝库，宝库旁边，画着另一张地图。他按图走到第一间宝库，里面是空的，只有一行小字：你找的不是这里。他又走，又空。每一间都更近，每一间都更空。第七间的墙上写着：所有地图，画的都是同一个地方——画图的人自己。勇者笑了。那是他这辈子第一次笑。他后来才知道，怀疑不是失败的开始，怀疑本身就是一种抵达',
  },
  3: {
    t: '火把',
    body: '勇者点亮火把。火光照见墙上一行字：你已经来过了。他低头数自己的脚印，只数出半程。另外半程，是别人替他走的。他站了很久，然后把火把举高了一点。就在那一刻，墙上浮出第二行字：你愿意把这一切再走一遍吗？连那些空房间，连那些谎言，连你自己的害怕。勇者没有回答。但火把没有放下。这是他对永恒所能给出的、唯一的答复',
  },
  4: {
    t: '大火',
    body: '最终勇者打败了恶龙，救出公主，可是恶龙死了，勇者死了，最后一场大火🔥烧掉了一切.....没有人记得那把火是谁点的。只有一件事留了下来：门从来没有锁过，龙从来没有守过什么，公主也从来没有在等谁来救。他们三个，被同一个故事骗了——讲故事的，是那条路本身。而路还在。灰烬下面，还有一双没走完的脚',
  },
};

/* ------------------------------------------------------------------ *
 * 每个关卡一个独立库
 * ------------------------------------------------------------------ */
let SQL = null;
const DBS = {};

// sleep() 捕获器：不真的阻塞进程，只记下"该等多久"，由 HTTP 层异步延时
let sleepMs = 0;

function seedAll() {
  const ids = SINGLE ? [SINGLE] : [1, 2, 3, 4];
  for (const id of ids) {
    if (DBS[id]) { try { DBS[id].close(); } catch (_) {} }
    const db = new SQL.Database();

    db.create_function('md5', (s) => crypto.createHash('md5').update(String(s)).digest('hex'));
    // 假 sleep：只登记延时，不阻塞事件循环（否则一个请求能把整站卡住）
    db.create_function('sleep', (n) => {
      sleepMs = Math.min(Math.max(Number(n) || 0, 0), 5) * 1000;
      return 1;
    });

    db.run(`CREATE TABLE b4bsql (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL
    );`);

    const rows = PUBLIC_ROWS.slice();
    if (id >= 3) rows.push(['flag', FLAGS[id]]); // L3/L4：flag 就在这一行的 password 里

    const ins = db.prepare('INSERT INTO b4bsql (username, password) VALUES (?, ?)');
    for (const [u, p] of rows) ins.run([u, p]);
    ins.free();

    // L2：flag 藏在需要靠 sqlite_master 问出来的表里，旁边放几个诱饵
    if (id === 2) {
      db.run('CREATE TABLE l2_secret_9f3 (id INTEGER PRIMARY KEY, code TEXT)');
      db.run('INSERT INTO l2_secret_9f3 (code) VALUES (?)', [FLAGS[2]]);
      db.run('CREATE TABLE l2_noise_0a1 (id INTEGER PRIMARY KEY, note TEXT)');
      db.run("INSERT INTO l2_noise_0a1 (note) VALUES ('nothing here, keep looking')");
      db.run('CREATE TABLE l2_decoy_77 (id INTEGER PRIMARY KEY, code TEXT)');
      db.run("INSERT INTO l2_decoy_77 (code) VALUES ('flag{you_wish_this_was_it}')");
    }

    DBS[id] = db;
  }
}

/* ------------------------------------------------------------------ *
 * 过滤：就是这几行，别在生产里这么写
 * ------------------------------------------------------------------ */
const WORDS_SINGLE = ['and', 'or', 'union', 'select', 'where', 'from'];
const WORDS_RECURSIVE = ['union', 'select', 'where', 'from', 'information_schema', 'sqlite_master', 'group_concat'];

// 单次删除：删一遍就走，双写可绕
function stripOnce(s) {
  let out = s;
  for (const w of WORDS_SINGLE) out = out.replace(new RegExp(w, 'gi'), '');
  return out;
}

// 递归删除：删到不再变化，双写失效；再把空白全部抹掉
function stripRecursive(s) {
  let prev;
  do {
    prev = s;
    for (const w of WORDS_RECURSIVE) s = s.replace(new RegExp(w, 'gi'), '');
  } while (s !== prev);
  return s.replace(/\s+/g, '');
}

function applyFilter(level, s) {
  const f = LEVELS[level].filter;
  if (f === 'single') return stripOnce(s);
  if (f === 'recursive') return stripRecursive(s);
  return s;
}

/* ------------------------------------------------------------------ *
 * 有漏洞的查询
 * ------------------------------------------------------------------ */
function login(level, username, password) {
  username = applyFilter(level, username);
  password = applyFilter(level, password);

  let sql = `SELECT * FROM b4bsql WHERE username='${username}' AND password=md5('${password}')`;

  // 方言补丁：MySQL 的 # 在 SQLite 里不存在，等价成 --（行注释）
  sql = sql.replace(/#/g, '--');

  sleepMs = 0;
  let stmt;
  try {
    stmt = DBS[level].prepare(sql);
  } catch (e) {
    return { kind: 'error', sleep: sleepMs };
  }

  let row = null;
  try {
    if (stmt.step()) row = stmt.get();
  } catch (e) {
    stmt.free();
    return { kind: 'error', sleep: sleepMs };
  }
  stmt.free();

  if (!row) return { kind: 'wrong', sleep: sleepMs };
  return { kind: 'success', row, sleep: sleepMs };
}

/* ------------------------------------------------------------------ *
 * 页面骨架
 * ------------------------------------------------------------------ */
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const shell = (title, body, accent, bg) => `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>神隐の最終兵器SQL城堡 · ${title}</title>
<style>
  :root{--accent:${accent || '#22D3EE'}}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;justify-content:flex-end;
       padding:36px 64px;background:#0B1118 url("/assets/${bg || 'hero-result.jpg'}") ${bg ? 'center' : 'right center'}/cover no-repeat fixed;
       font-family:"Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;color:#EAF2FA}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
       background:linear-gradient(90deg,rgba(11,17,24,.10) 0%,rgba(11,17,24,.45) 55%,rgba(11,17,24,.80) 100%)}
  .card{position:relative;z-index:1;width:560px;padding:38px 40px;margin:auto 0;
       background:rgba(11,17,24,.78);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);
       border:1px solid #3B4D62;border-radius:20px;box-shadow:0 28px 70px rgba(0,0,0,.6)}
  .pill{display:inline-block;padding:6px 12px;border-radius:999px;font-size:11px;font-weight:600;
       letter-spacing:1px;background:#0F2E24;color:#34D399;border:1px solid #1E5B47}
  h1{font-size:34px;margin:16px 0 6px}
  hr{border:0;border-top:1px solid #1E2833;margin:18px 0}
  .line{font-size:18px;margin:10px 0}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;color:#22D3EE;word-break:break-all}
  .note{font-size:11px;color:#7F8FA0;margin-top:18px}
  .curse{font-size:26px;font-weight:900;line-height:1.45;color:#FFFFFF;margin:20px 0 0}
  .quip{margin:22px 0 0;padding:14px 16px;border:1px solid #4A3A18;background:#1A1408;border-radius:12px}
  .quip b{display:block;font-size:11px;letter-spacing:1.5px;color:#FBBF24;margin-bottom:8px}
  .quip p.lead{margin:0 0 12px;font-size:20px;font-weight:900;line-height:1.55;color:#FFD166;
       text-shadow:0 2px 14px rgba(251,191,36,.35)}
  .quip span{font-size:16px;font-weight:700;line-height:1.65;color:#F0E6D2}
  .reward{display:block;width:100%;max-height:240px;object-fit:cover;object-position:center;
       border-radius:12px;margin:18px 0 0;border:1px solid #3B4D62}
  .hintgirl{display:block;width:100%;border-radius:12px;margin:0 0 22px;border:1px solid #3B4D62}
  .shout{position:fixed;left:64px;top:96px;z-index:1;width:560px;
         font-size:46px;font-weight:900;line-height:1.16;color:#FFFFFF;transform:rotate(-3deg)}
  .flagbox{margin:20px 0 0;padding:16px 18px;border-radius:12px;
       background:#07170F;border:1px solid #1E5B47;font-family:ui-monospace,Menlo,Consolas,monospace;
       font-size:15px;color:#34D399;word-break:break-all}
  .flagbox em{display:block;font-family:"Noto Sans SC",system-ui,sans-serif;font-style:normal;
       font-size:11px;letter-spacing:1px;color:#4ED8A0;margin-bottom:8px}
  .story{margin:18px 0 0;padding:16px 18px;border-left:2px solid var(--accent);
       background:rgba(0,0,0,.28);border-radius:0 10px 10px 0;
       font-size:14px;line-height:1.95;color:#D6E2EE;white-space:pre-line}
  .story b{display:block;font-size:10px;letter-spacing:2px;color:var(--accent);
       margin-bottom:10px;font-weight:700}
  .row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
  .tab{flex:1 1 0;min-width:64px;text-align:center;padding:8px 0;border-radius:9px;font-size:12px;
       text-decoration:none;color:#8FA3B8;border:1px solid #22303F;background:#0C131B}
  .tab.on{color:#06121A;font-weight:700;background:var(--accent);border-color:var(--accent)}
  .tab b{display:block;font-size:9px;letter-spacing:.5px;opacity:.75;margin-top:2px;font-weight:600}
  a{color:var(--accent)}
  @media(max-width:760px){
    body{justify-content:center;padding:20px}
    body::before{background:rgba(11,17,24,.66)}
    .card{width:100%;padding:28px 22px}
    h1{font-size:26px}
    .shout{left:20px;right:20px;top:24px;width:auto;font-size:24px}
  }
</style></head><body>${body}</body></html>`;

/* ------------------------------------------------------------------ *
 * 提示语
 *   前两关是教学关，提示会指路；
 *   后两关只嘲讽不指路 —— 想指路得去 /hint，且要失败够次数才解锁
 * ------------------------------------------------------------------ */
const Q = {
  flag: { tag: 'CLEARED', text: 'the seal is off. but ask urself: if this castle were built with bound params, what would ur whole spell be worth? nothing. a dead word.' },
  comment: { tag: 'STAGE 1 · COMMENT', text: 'the first seal broke. a comment devoured the password and the password never screamed. nxt: count the thrones.' },
  unionError: { tag: 'COL MISMATCH', text: 'the columns do not align with the stars. add one, and one more, until the void stops rejecting u.' },
  unionOk: { tag: 'ECHO SPOT', text: 'three thrones. col 2 speaks as the name, col 3 speaks as the secret. all data leaves thru these two mouths only.' },
  orderBy: { tag: 'COUNTER', text: 'counting is the prayer of the patient. the number u want is how many mouths this room has — guess one too many and the whole sentence dies.' },
  infoSchema: { tag: 'SCHEMA?', text: 'information_schema does not exist in this universe. this castle keeps its own book of names — and u are one query away from it.' },
  schemaOk: { tag: 'BOOK OF NAMES', text: 'right book. but the index only says which shelf to walk to — it never tells u what u came for. open the page.' },
  fakeFlag: { tag: 'DECOY', text: 'that flag is a lie. planted for whoever grabs the first thing that shines. dig deeper.' },
  eaten: { tag: 'WORD EATEN', text: 'one of ur words was swallowed whole before it could stand. the sentence lost its spine. say that word twice and it walks again.' },
  halfOpen: { tag: 'HALF OPEN', text: 'u doubled the dead word and the filter blinked. good instinct. but the row u asked for does not exist — name someone who does, or make the whole room kneel for u.' },
  emptyVault: { tag: 'NOT THE FLAG', lead: '别什么都用万能啥的啊，混蛋！这里没有 flag', text: '门是开了，可你站的是空屋子。让屋子自己开口：三个位子，还有一本知道所有名字的书。' },
  passwd: { tag: 'FIELD TRAP', text: 'the word "password" carries "or" inside it like a parasite. it gets eaten. say it twice and it walks out alive.' },
  groupConcat: { tag: 'GREEDY', text: 'u try to swallow the whole table in one bite. greed. one argument only — stitch the bones with ||.' },
  sleep: { tag: 'NO SLEEP', text: 'time is not a weapon on this floor. u have a mouth that speaks. use it.' },
  blind: { tag: 'BLIND', text: 'one char at a time, like counting stars in a dead sky. admirable. and completely unnecessary here.' },
  likeBlind: { tag: 'BLIND · LIKE', text: 'no union? then LIKE is the only god left in the room. brute it, one char at a time, and do not blink.' },
  quoteErr: { tag: 'QUOTE OPEN', text: 'a lone quote hangs in the void. the sentence died mid-breath. close it — or kill everything behind it.' },
  syntax: { tag: 'SYNTAX', text: 'the statement collapsed. check three things: the quotes, the brackets, and which word the dark quietly ate.' },
};

// L3：只嘲讽，不给方向
const Q3 = {
  miss: { tag: 'SILENT ROOM', text: 'the room returns nothing. it never did. not to u, not to anyone before u.' },
  hit: { tag: 'A HIT, AND YET', text: 'a yes. and still zero data in ur hands. a yes is a coin — spend it on the right question.' },
  err: { tag: 'BROKEN', text: 'broken. and no god will come down to tell u why.' },
};

function pickQuip(level, u, p, kind, row) {
  const meta = LEVELS[level];

  if (meta.quips === 'none') return null;

  if (meta.quips === 'taunt') {
    if (kind === 'error') return Q3.err;
    return kind === 'success' ? Q3.hit : Q3.miss;
  }

  // 教学关
  const s = (u + ' ' + p).toLowerCase();
  const has = (re) => re.test(s);

  // 只有本关"真 flag"才算通关；诱饵表里的假 flag 单独给一句
  const hitFlags = (row || []).filter((v) => typeof v === 'string' && v.indexOf('flag{') !== -1);
  if (hitFlags.length) return hitFlags.includes(FLAGS[level]) ? Q.flag : Q.fakeFlag;

  const attempt = has(/'|"|#|\(|\)|--/)
    || has(/\b(union|select|from|where|order|sleep|benchmark|group_concat|information_schema|ascii|substr|mid)\b/);
  if (!attempt) return null;

  if (has(/oorrder|order\s*by/)) return Q.orderBy;

  // 第二关：单次补丁的两种典型翻车 —— 词被整个吃掉 / 双写成功但句子还是死的
  if (level === 2) {
    const raw = (u + ' ' + p).toLowerCase();
    const once = stripOnce(raw);
    const eatenWord = WORDS_SINGLE.find((w) => (
      new RegExp(`\\b${w}\\b`).test(raw) && !new RegExp(`\\b${w}\\b`).test(once)
    ));
    if (eatenWord && kind === 'error') return Q.eaten;
    const doubled = WORDS_SINGLE.some((w) => new RegExp(`\\b${w}\\b`).test(once));
    if (doubled && kind !== 'success') return Q.halfOpen;
  }

  if (has(/infoorrmation|information_schema/)) return Q.infoSchema;
  if (has(/sqlite_master/)) return Q.schemaOk;
  if (has(/group_concat/) && level >= 3) return Q.groupConcat;
  if (has(/\blike\b/)) return Q.likeBlind;
  if (has(/passwoorrd|password/)) return Q.passwd;
  if (has(/sleep|benchmark/)) return Q.sleep;
  if (has(/ascii|substr|substring|mid\s*\(/)) return Q.blind;
  if (has(/ununionion|union/)) return kind === 'error' ? Q.unionError : Q.unionOk;

  // 万能密码 / 注释绕过：门开了，但旗不在这间屋子 —— 第二关统一说这句
  if (level === 2 && kind === 'success' && has(/'/)) return Q.emptyVault;

  if (has(/#|--/) && kind === 'success') return Q.comment;
  if (has(/'/) && kind === 'error') return Q.quoteErr;
  if (kind === 'error') return Q.syntax;
  if (kind === 'success') return Q.emptyVault;
  return null;
}

const QUIP_PREFIX = '你什么都做不到，命运的钟声在回响....';
const quipHtml = (q) => (q
  ? `<div class="quip">${q.lead ? `<p class="lead">${esc(q.lead)}</p>` : ''}<b>${esc(q.tag)}</b><span>${QUIP_PREFIX}${esc(q.text)}</span></div>`
  : '');

/* ------------------------------------------------------------------ *
 * 结果页
 * ------------------------------------------------------------------ */
const pageOnly = () => shell('404', `
  <div class="card">
    <h1 style="font-size:26px">404</h1>
    <p class="line" style="font-size:14px;color:#A08A8E">这一关不在这台靶机上。四个关卡是四个独立容器。</p>
    <p class="note"><a href="/">← 回本关</a></p>
  </div>`, '#7F8FA0', 'fail-bg.jpg');

const tabs = (active) => `<div class="row">${(SINGLE ? [SINGLE] : [1, 2, 3, 4]).map((i) => {
  const m = LEVELS[i];
  return `<a class="tab${i === active ? ' on' : ''}" href="/?lv=${i}">L${i}<b>${m.diff}</b></a>`;
}).join('')}</div>`;

/* 引路人：每关通关后说一句，跟这一章故事的结尾对着来 */
const GUIDE = {
  1: '引路人别过脸去：「哼、门没锁也算你的功劳？」她声音小下去，「……灯灭了我会点。你只管往前走」',
  2: '引路人踢了踢地上的图：「空的那几间，本来就没给你留。」她抬眼看你，「兜里那张重了？……笨蛋」',
  3: '引路人把火把塞进你手里：「再来一次，是你自己点的头哦。」她别过头，「……我可没逼你。哼」',
  4: '引路人站在灰烬里，没再别过脸：「龙死了，勇者也死了。」她顿了顿，「……你还要走吗？哼，问都问出口了」',
};

const rewardBlock = (level) => `
    <img class="reward" src="/assets/reward.jpg" alt="她抬头看着天">
    <p class="curse" style="margin:22px 0 0;font-size:20px">${esc(GUIDE[level] || GUIDE[1])}</p>`;

// 通关后放一章故事：前三章是前传，第四章是结局与尾声
const storyHtml = (level) => (STORY[level]
  ? `<div class="story"><b>CHAPTER ${level} · ${esc(STORY[level].t)}</b>${esc(STORY[level].body)}</div>`
  : '');

function pageError(level, q) {
  const m = LEVELS[level];
  return shell('Error', `
  <div class="card">${tabs(level)}
  <span class="pill" style="background:#2A1315;color:#F87171;border-color:#5A2228">SQL ERROR</span>
  <h1 style="color:#F87171">Error!</h1>
  <p class="line" style="font-size:14px;color:#A08A8E">语句没有执行成功。</p>
  ${quipHtml(q)}
  <p class="note"><a href="/?lv=${level}">← 返回第 ${level} 关</a> · <a href="/hint?lv=${level}">要看提示？先多失败几次</a></p></div>`, m.accent);
}

function pageWrong(level, q) {
  const m = LEVELS[level];
  return shell('Wrong', `
  <div class="card">${tabs(level)}
  <span class="pill" style="background:#2A1315;color:#F87171;border-color:#5A2228">LOGIN FAILED</span>
  <h1 style="color:#F87171;font-size:26px;margin:16px 0 0">NO,Wrong username password</h1>
  <p class="curse">你什么都做不到，命运的钟声在回响....</p>
  <p class="curse" style="margin:14px 0 0;font-size:22px">甘愿如此吗，在你的世界恶龙是谁？挥剑，向前！！命运？可笑的风车</p>
  ${quipHtml(q)}
  <p class="note" style="margin-top:24px">查到了 0 行。条件为假，或者账号根本不存在。</p>
  <p class="note"><a href="/?lv=${level}">← 返回第 ${level} 关</a> · <a href="/hint?lv=${level}">提示</a></p></div>`, m.accent, 'fail-bg.jpg');
}

function pageSuccess(level, row, q) {
  const m = LEVELS[level];
  const values = [];
  for (let i = 0; i < row.length; i++) values.push(row[i]);
  const col2 = esc(values[1] === undefined ? '' : values[1]);
  const col3 = esc(values[2] === undefined ? '' : values[2]);
  const found = values.find((v) => typeof v === 'string' && v.indexOf('flag{') !== -1);

  // 第一关：只要登录成功就发 flag
  // 盲注关（echo !== full）不给 flagbox —— 否则一命中就把答案印在页面上，盲注白设计了
  let flagbox = '';
  if (level === 1) {
    flagbox = `<div class="flagbox"><em>L1 CLEARED</em>${FLAGS[1]}</div>`;
  } else if (m.echo === 'full' && found && found === FLAGS[level]) {
    flagbox = `<div class="flagbox"><em>L${level} CLEARED</em>${esc(found)}</div>`;
  }

  // 第三关不回显任何数据
  const dataBlock = m.echo === 'full'
    ? `<p class="line">Hello ${col2}！</p>
    <p class="mono">Your password is ${col3}</p>`
    : `<p class="note" style="color:#FBBF24;margin:0 0 6px">这一关不回显任何数据</p>
    <p class="note" style="margin:0">你知道的只有一件事：这次命中了。</p>`;

  return shell('Login Success', `
  <div class="shout">哒哒哒，<br>好想玩原神，云原神！</div>
  <div class="card">${tabs(level)}
    <span class="pill">HTTP 200 · LOGIN SUCCESS</span>
    <h1>Login Success!</h1>
    <hr>
    ${dataBlock}
    ${flagbox}
    ${flagbox ? storyHtml(level) : ''}
    ${flagbox ? rewardBlock(level) : ''}
    ${quipHtml(q)}
    <hr>
    <p class="note"><a href="/?lv=${level}">← 第 ${level} 关</a> · <a href="/hint?lv=${level}">提示</a> · <a href="/score">计分板</a></p>
  </div>`, m.accent);
}

// L4：三态同一页面，一个字节都不差
const pageSilent = () => shell('登录', `
  <div class="card">
    <span class="pill" style="background:#1A1F27;color:#8FA3B8;border-color:#2A3542">HTTP 200</span>
    <h1 style="font-size:26px">登录处理完毕</h1>
    <p class="note" style="margin-top:24px">神没有回答你。</p>
    <p class="note"><a href="/?lv=4">← 第 4 关</a> · <a href="/hint?lv=4">提示</a> · <a href="/score">计分板</a></p>
  </div>`, LEVELS[4].accent);

/* ------------------------------------------------------------------ *
 * 渐进式提示：失败够次数才解锁
 * ------------------------------------------------------------------ */
const HINTS = {
  1: [
    'ur words are already inside a pair of quotes. u did not break in — u were already the wall.',
    'every sentence ends. make the rest of it die quietly, and nobody will ask about the password.',
    'close the quote. then let the universe forget everything behind it. one symbol is enough.',
  ],
  2: [
    'the words were killed once. once is not forever, child.',
    'say it twice. the middle one dies, and the echo walks out alive.',
    'three thrones, two mouths. the treasure is not in this kingdom — ask the one who keeps the book of names.',
  ],
  3: [
    'this room deletes until nothing changes. ur echoes die before they can return to u.',
    'space is a luxury here. the void between two words must be borrowed from the dark.',
    'no union. no select. u are already standing inside the table u came for.',
    'the universe answers only yes or no now. learn to ask small questions.',
    'the row u want is named after the very thing u came here for.',
    'still copying writeups? it shows. the abyss is not impressed.',
  ],
  4: [
    'three answers, one silence. the shape of the reply will never change — only its weight in time.',
    'time is the last god left in this castle. it answers everything, just slowly.',
    'AND is lazy. if the left hand lies, the right hand never moves at all.',
    'make the question cost a second. in the dark, one second is a scream.',
    'short-circuit is not a bug in this world. it is the only language left.',
    'the network lies more often than this castle. measure a floor first, then trust only what clears it twice.',
    'the abyss is patient. u are not.',
  ],
};

const fails = new Map(); // `${ip}|${lv}` -> 次数
const bumpFail = (ip, lv) => {
  const k = `${ip}|${lv}`;
  const n = (fails.get(k) || 0) + 1;
  fails.set(k, n);
  if (fails.size > 20000) fails.clear();
  return n;
};
const hintUnlocked = (lv, i, ip) => {
  if (lv <= 2) return true;
  return (fails.get(`${ip}|${lv}`) || 0) >= 8 * (i + 1);
};

/* ------------------------------------------------------------------ *
 * 计分板
 * ------------------------------------------------------------------ */
const SCORE_FILE = path.join(__dirname, 'data', 'scoreboard.json');
const scoreboard = []; // {name, lv, at}
const solvedLevels = new Set();

function loadScore() {
  try {
    const o = JSON.parse(fs.readFileSync(SCORE_FILE, 'utf8'));
    if (Array.isArray(o.scores)) scoreboard.push(...o.scores.slice(-500));
    if (Array.isArray(o.solved)) o.solved.forEach((x) => solvedLevels.add(x));
    if (Array.isArray(o.ip)) o.ip.forEach(([k, v]) => SUBMIT_BY_IP.set(k, v));
    return scoreboard.length;
  } catch (_) { return 0; }
}
function saveScore() {
  try {
    fs.mkdirSync(path.dirname(SCORE_FILE), { recursive: true });
    fs.writeFileSync(SCORE_FILE, JSON.stringify({
      scores: scoreboard.slice(-500),
      solved: [...solvedLevels],
      ip: [...SUBMIT_BY_IP],
    }));
  } catch (_) {}
}
function clearScore() {
  scoreboard.length = 0;
  solvedLevels.clear();
  SUBMIT_BY_IP.clear();
  saveScore();
}

// 同名只留一条，关卡取最高的那次
function upsertScore(name, lv, at) {
  const t = (at || '').slice(0, 16) || fmtTs(Date.now());
  const i = scoreboard.findIndex((e) => e.name === name);
  if (i === -1) {
    scoreboard.push({ name, lv, at: t });
    if (scoreboard.length > 500) scoreboard.shift();
  } else if (lv > scoreboard[i].lv) {
    scoreboard[i] = { name, lv, at: t };
  }
}

// 同一 IP 最多成功提交 10 次
const SUBMIT_BY_IP = new Map();
const SUBMIT_MAX_PER_IP = 10;

const pageScore = () => {
  const rows = scoreboard.slice().reverse().map((e) => (
    `<tr><td style="padding:8px 10px">${esc(e.name)}</td><td style="padding:8px 10px">L${e.lv}</td><td style="padding:8px 10px;color:#7F8FA0">${esc(e.at)}</td></tr>`
  )).join('') || '<tr><td colspan="3" style="padding:14px 10px;color:#7F8FA0">还没人交 flag。</td></tr>';
  return shell('Scoreboard', `
  <div class="card" style="width:640px">
    <span class="pill">SCOREBOARD</span>
    <h1 style="font-size:26px">计分板</h1>
    <p class="note" style="margin:0 0 16px">把拿到的 flag 交到 /submit?lv=..&amp;flag=..&amp;name=..</p>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="color:#7F8FA0;text-align:left"><th style="padding:8px 10px">name</th><th style="padding:8px 10px">level</th><th style="padding:8px 10px">time</th></tr>
      ${rows}
    </table>
    <p class="note"><a href="/">← 回首页</a></p>
  </div>`, '#22D3EE', 'fail-bg.jpg');
};

const pageSubmit = (ok, lv) => shell('Submit', `
  <div class="card">
    <span class="pill" ${ok ? '' : 'style="background:#2A1315;color:#F87171;border-color:#5A2228"'}>${ok ? 'ACCEPTED' : 'REJECTED'}</span>
    <h1 style="font-size:28px">${ok ? 'flag 正确' : '这不是那个 flag'}</h1>
    <p class="line" style="font-size:14px;color:#A08A8E">${ok
      ? `第 ${lv} 关已记录。${solvedLevels.has(lv) ? '解法页已解锁：<a href="/writeup?lv=' + lv + '">看 writeup</a>' : ''}`
      : '别急，慢慢来。'}</p>
    ${ok ? storyHtml(lv) : ''}
    ${ok ? rewardBlock(lv) : ''}
    <p class="note"><a href="/?lv=${lv || 1}">← 继续</a> · <a href="/score">计分板</a></p>
  </div>`, ok ? '#34D399' : '#F87171');

/* ------------------------------------------------------------------ *
 * 访问统计：内存聚合 + 追加写 data/visits.log，启动时回放历史
 *   重新发布前把线上日志拉回来合并，历史就不会丢
 * ------------------------------------------------------------------ */
const STATS_KEY = process.env.STATS_KEY || 'shen7yin';
const DATA_DIR = path.join(__dirname, 'data');
const LOG_FILE = path.join(DATA_DIR, 'visits.log');

const VISITS = new Map();   // vid -> { first, last, hits, ua, levels:Set, solved:Set, ips:Set }
const DAY_HITS = new Map(); // 'YYYY-MM-DD' -> { hits, ips:Set }
let TOTAL_HITS = 0;

// 平台网关的 X-Forwarded-For 给的是它自己的节点地址（同一人刷新会跳 IP），
// 所以"多少人"按浏览器 cookie 去重，IP 只当参考。
const getVid = (req, res) => {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)vid=([A-Za-z0-9_-]{6,40})/);
  if (m) return m[1];
  const vid = crypto.randomUUID();
  try { res.setHeader('Set-Cookie', `vid=${vid}; Max-Age=31536000; Path=/; SameSite=Lax`); } catch (_) {}
  return vid;
};

const bjDay = (offset) => new Date(Date.now() + 8 * 3600e3 - (offset || 0) * 86400e3).toISOString().slice(0, 10);
const fmtTs = (ts) => new Date(ts + 8 * 3600e3).toISOString().slice(5, 16).replace('T', ' ');
const maskIp = (ip) => {
  if (!ip) return '?';
  if (ip.indexOf(':') !== -1) return ip.split(':').slice(0, 3).join(':') + ':…';
  const p = ip.split('.');
  return p.length === 4 ? `${p[0]}.${p[1]}.*.*` : ip;
};

// 入账（实时与日志回放共用同一条路径）
function ingest(vid, ip, ua, lv, ts) {
  TOTAL_HITS++;
  let v = VISITS.get(vid);
  if (!v) {
    v = { first: ts, last: ts, hits: 0, ua: ua || '', levels: new Set(), solved: new Set(), ips: new Set() };
    VISITS.set(vid, v);
    if (VISITS.size > 20000) {
      let oldKey = null, oldLast = Infinity;
      for (const [k, x] of VISITS) if (x.last < oldLast) { oldLast = x.last; oldKey = k; }
      if (oldKey) VISITS.delete(oldKey);
    }
  }
  if (ts > v.last) v.last = ts;
  if (ts < v.first) v.first = ts;
  v.hits++;
  if (lv) v.levels.add(lv);
  if (ip && ip !== 'unknown') v.ips.add(ip);

  const d = new Date(ts + 8 * 3600e3).toISOString().slice(0, 10);
  let day = DAY_HITS.get(d);
  if (!day) { day = { hits: 0, ips: new Set() }; DAY_HITS.set(d, day); }
  day.hits++;
  day.ips.add(vid);
  if (DAY_HITS.size > 120) DAY_HITS.delete([...DAY_HITS.keys()].sort()[0]);
}

function loadLog() {
  let n = 0;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const txt = fs.readFileSync(LOG_FILE, 'utf8');
    for (const line of txt.split('\n')) {
      if (!line) continue;
      let e; try { e = JSON.parse(line); } catch (_) { continue; }
      if (!e || !e.v || !e.t) continue;
      ingest(e.v, e.i, e.u, e.l, e.t);
      n++;
    }
  } catch (_) {}
  return n;
}

function appendLog(e) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.appendFileSync(LOG_FILE, JSON.stringify(e) + '\n');
  } catch (_) {}
}

// 平台会把同一个请求回源两次（两个后端各记一遍），3 秒内同 vid 同路径只算一次
const RECENT = new Map();
function recordVisit(vid, ip, req, lv, path) {
  const ts = Date.now();
  const k = vid + '|' + path;
  const last = RECENT.get(k);
  if (last && ts - last < 3000) return;
  if (RECENT.size > 8000) RECENT.clear();
  RECENT.set(k, ts);

  const ua = String(req.headers['user-agent'] || '').slice(0, 90);
  ingest(vid, ip, ua, lv, ts);
  appendLog({ t: ts, v: vid, i: ip, l: lv || 0, u: ua });
}

const pageStats = (key, full) => {
  if (key !== STATS_KEY) {
    return shell('Stats', `
    <div class="card">
      <h1 style="font-size:26px">404</h1>
      <p class="line" style="font-size:14px;color:#A08A8E">这里没有你要看的东西。</p>
      <p class="note"><a href="/">← 回首页</a></p>
    </div>`, '#7F8FA0', 'fail-bg.jpg');
  }

  const today = DAY_HITS.get(bjDay()) || { hits: 0, ips: new Set() };
  const list = [...VISITS.entries()].sort((a, b) => b[1].last - a[1].last);
  const solvers = list.filter(([, v]) => v.solved.size).length;

  const days = [];
  for (let i = 6; i >= 0; i--) days.push([bjDay(i), DAY_HITS.get(bjDay(i)) || { hits: 0, ips: new Set() }]);
  const peak = Math.max(1, ...days.map(([, x]) => x.ips.size));
  const bars = days.map(([d, x]) => {
    const n = x.ips.size;
    const bar = '█'.repeat(Math.max(0, Math.round((n / peak) * 16))) || '·';
    return `<div style="font-size:12px;color:#9FB3C8;margin:5px 0">
      <span style="color:#7F8FA0">${d.slice(5)}</span>
      <span style="color:#22D3EE;letter-spacing:1px">${bar}</span>
      <span style="color:#EAF2FA">${n}</span> 人 / ${x.hits} 次</div>`;
  }).join('');

  const rows = list.slice(0, 40).map(([vid, v]) => {
    const ips = [...v.ips];
    const ipCell = ips.length
      ? ips.slice(0, 2).map((x) => esc(full ? x : maskIp(x))).join('<br>') + (ips.length > 2 ? `<br><span style="color:#5C6B7A">+${ips.length - 2}</span>` : '')
      : '—';
    return `
    <tr>
      <td style="padding:7px 8px;font-family:ui-monospace,monospace;font-size:11px;color:#9FB3C8">#${esc(vid.slice(0, 6))}</td>
      <td style="padding:7px 8px;font-family:ui-monospace,monospace;font-size:12px">${ipCell}</td>
      <td style="padding:7px 8px;font-size:12px;color:#22D3EE">${v.hits}</td>
      <td style="padding:7px 8px;font-size:12px;color:#9FB3C8">${esc([...v.levels].sort().map((l) => 'L' + l).join(' ') || '—')}</td>
      <td style="padding:7px 8px;font-size:12px;color:${v.solved.size ? '#34D399' : '#5C6B7A'}">${v.solved.size ? [...v.solved].sort().join(' / ') : '—'}</td>
      <td style="padding:7px 8px;font-size:11px;color:#7F8FA0;white-space:nowrap">${fmtTs(v.first)} → ${fmtTs(v.last)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="6" style="padding:16px 8px;color:#7F8FA0">还没有人访问。</td></tr>';

  return shell('Stats', `
  <div class="card" style="width:900px;max-width:calc(100vw - 80px)">
    <span class="pill">VISITORS</span>
    <h1 style="font-size:26px">访问统计</h1>
    <div style="display:flex;gap:14px;margin:6px 0 18px;flex-wrap:wrap">
      <div style="flex:1;min-width:150px;padding:14px 16px;border:1px solid #2B3B4D;border-radius:12px;background:#0F161F">
        <div style="font-size:11px;color:#7F8FA0;letter-spacing:1px">独立访客（累计）</div>
        <div style="font-size:28px;font-weight:800;color:#22D3EE">${list.length}</div>
      </div>
      <div style="flex:1;min-width:150px;padding:14px 16px;border:1px solid #2B3B4D;border-radius:12px;background:#0F161F">
        <div style="font-size:11px;color:#7F8FA0;letter-spacing:1px">今日访客</div>
        <div style="font-size:28px;font-weight:800;color:#34D399">${today.ips.size}</div>
      </div>
      <div style="flex:1;min-width:150px;padding:14px 16px;border:1px solid #2B3B4D;border-radius:12px;background:#0F161F">
        <div style="font-size:11px;color:#7F8FA0;letter-spacing:1px">今日请求</div>
        <div style="font-size:28px;font-weight:800">${today.hits}</div>
      </div>
      <div style="flex:1;min-width:150px;padding:14px 16px;border:1px solid #2B3B4D;border-radius:12px;background:#0F161F">
        <div style="font-size:11px;color:#7F8FA0;letter-spacing:1px">累计请求 / 通关人数</div>
        <div style="font-size:28px;font-weight:800">${TOTAL_HITS}<span style="font-size:14px;color:#7F8FA0"> / ${solvers}</span></div>
      </div>
    </div>
    <div style="margin:0 0 20px">${bars}</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="color:#7F8FA0;text-align:left">
        <th style="padding:8px">访客</th><th style="padding:8px">${full ? 'IP（完整）' : 'IP（打码）'}</th><th style="padding:8px">请求</th>
        <th style="padding:8px">打过的关</th><th style="padding:8px">拿到 flag</th><th style="padding:8px">首末访问</th>
      </tr>
      ${rows}
    </table>
    <p class="note">人数按浏览器 cookie（<code>vid</code>）去重，刷新不会重复计；换浏览器 / 无痕 / 清了 cookie 会被算成新访客。
      平台网关回源的 IP 是它自己的节点地址，同一人刷新也可能变，所以 IP 那列只能当参考。
      看完整 IP 加 <code>&amp;full=1</code>。数据在内存里，重新发布或实例重启会清零。</p>
    <p class="note"><a href="/">← 回首页</a> · <a href="/score">计分板</a></p>
  </div>`, '#22D3EE', 'fail-bg.jpg');
};

const pageTooMany = () => shell('Too Many', `
  <div class="card">
    <span class="pill" style="background:#2A1315;color:#F87171;border-color:#5A2228">429 · TOO MANY</span>
    <h1 style="font-size:28px">够了</h1>
    <p class="line" style="font-size:14px;color:#A08A8E">同一个 IP 已经成功提交过 ${SUBMIT_MAX_PER_IP} 次。占榜可以，别把榜占满。</p>
    <p class="note"><a href="/score">← 计分板</a></p>
  </div>`, '#F87171', 'fail-bg.jpg');

/* ------------------------------------------------------------------ *
 * writeup（有人交过该关 flag 才开放）
 * ------------------------------------------------------------------ */
const WRITEUPS = {
  1: {
    title: 'L1 · 深渊回望',
    body: `没有过滤，注入点就是 username：<br><br>
<code>SELECT * FROM b4bsql WHERE username='$u' AND password=md5('$p')</code><br><br>
payload：<code>admin'#</code> —— 单引号闭合字符串，<code>#</code> 把后面的密码判断注释掉。<br>
（SQLite 没有 <code>#</code>，本站做了等价转换，这不是"绕过"，是方言兼容。）`,
  },
  2: {
    title: 'L2 · 偶像的黄昏',
    body: `过滤是单次 <code>str_replace</code>：<code>and/or/union/select/where/from</code> 各删一遍。<br><br>
写两遍即可复原：<code>ununionion seselectlect</code>。<br><br>
列数 3，回显 2/3 列。flag 不在 b4bsql —— 先问表名：<br>
<code>x' ununionion seselectlect 1,2,name frfromom sqlite_master whwhereere type='table'#</code><br><br>
再取：<code>x' ununionion seselectlect 1,2,code frfromom l2_secret_9f3#</code><br>
（注意 <code>l2_decoy_77</code> 是诱饵。）`,
  },
  3: {
    title: 'L3 · 永恒轮回',
    body: `过滤改成循环删，双写失效；空格全部被抹掉，用 <code>/**/</code> 代替。<br><br>
union / select / from 都进不来 —— 但你不需要子查询，flag 就在你要查的那一行。<br><br>
先确认命中：<code>flag'/**/#</code><br>
再一位一位问：<code>flag'/**/and/**/substr(password,1,1)=char(102)/**/#</code><br><br>
命中 → 登录成功页；没命中 → 失败页。写个循环换下标和 char 值即可。`,
  },
  4: {
    title: 'L4 · 上帝已死',
    body: `过滤同 L3，且三种结果返回完全相同的页面 —— 唯一信道是耗时。<br><br>
<code>sleep()</code> 是本题挂的假函数，返回 1，但会登记延时；<br>
<code>AND</code> 会短路：左边为假，右边的 sleep 不执行。<br><br>
探测器：<code>flag'/**/and/**/sleep(3)/**/#</code> → 等 3 秒，说明通道成立。<br>
提问：<code>flag'/**/and/**/substr(password,1,1)=char(102)/**/and/**/sleep(3)/**/#</code><br><br>
命中则慢，未命中则快。逐位爆破即可。`,
  },
};

/* ------------------------------------------------------------------ *
 * 传输层解码（兼容明文 / 老 base64 / v2 异或+base64）
 *   平台网关会"先解 base64 再匹配关键词"，所以单层 base64 挡不住它。
 *   v2 在 base64 之前再异或一层：网关解出来是乱码，匹配不到任何关键字。
 *   注入本身一点没变，只是 HTTP 层看不见明文。
 * ------------------------------------------------------------------ */
const TX_TAG = 'v2:';
const TX_KEY = 'shen7yin';

function xorBuf(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ TX_KEY.charCodeAt(i % TX_KEY.length);
  return out;
}

const isB64 = (t) => t.length > 0 && t.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(t);

function maybeB64(s) {
  const t = String(s).trim();

  // v2：异或 + base64
  if (t.startsWith(TX_TAG)) {
    const body = t.slice(TX_TAG.length);
    if (!isB64(body)) return s;
    const plain = xorBuf(Buffer.from(body, 'base64'));
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(plain);
    } catch {
      return s;
    }
  }

  // 老 base64（手测/老链接）
  if (!isB64(t)) return s;
  const txt = Buffer.from(t, 'base64').toString('utf8');
  if (Buffer.from(txt, 'utf8').toString('base64') !== t) return s;
  return txt;
}

/* ------------------------------------------------------------------ *
 * 限流
 *   盲注爆破天生需要成千次请求，额度给小了等于把正常解法挡在门外。
 *   这里只防"无脑刷"，不防"正经写脚本"。
 * ------------------------------------------------------------------ */
const hits = new Map();
function rateLimited(ip, limit) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 10_000);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > (limit || 2000);
}

/* ------------------------------------------------------------------ *
 * 首页模板
 * ------------------------------------------------------------------ */
let INDEX_TPL = '';
function renderIndex(level) {
  const m = LEVELS[level];
  const rep = (tpl, tag, val) => tpl.split(tag).join(val); // 模板里同一占位符可能出现多次
  let out = rep(INDEX_TPL, '<!--TABS-->', tabs(level));
  out = rep(out, '<!--ACCENT-->', m.accent);
  out = rep(out, '<!--DIFF-->', m.diff);
  out = rep(out, '<!--NAME-->', esc(m.name));
  out = rep(out, '<!--SUB-->', esc(m.sub));
  out = rep(out, '<!--TECH-->', esc(m.tech || ''));
  out = rep(out, '<!--LV-->', String(level));
  return out;
}

/* ------------------------------------------------------------------ *
 * HTTP
 * ------------------------------------------------------------------ */
const MIME = { '.jpg': 'image/jpeg', '.png': 'image/png', '.css': 'text/css', '.js': 'application/javascript' };
const html = (res, body, code) => {
  res.writeHead(code || 200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
};

const server = http.createServer((req, res) => {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || 'unknown';

  if (rateLimited(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('请求太频繁，歇 10 秒再来。');
  }

  const url = new URL(req.url, 'http://localhost');
  const lvRaw = parseInt(url.searchParams.get('lv') || '1', 10);
  let lv = LEVELS[lvRaw] ? lvRaw : 1;
  // 单关卡模式：只认自己那一关，其他关一律 404
  if (SINGLE) {
    if (url.searchParams.has('lv') && lvRaw !== SINGLE) {
      return html(res, pageOnly(), 404);
    }
    lv = SINGLE;
  }

  // 访问统计：跳过静态资源与统计页自身；容器内（ADMIN_ON=0）不记录
  const vid = getVid(req, res);
  if (ADMIN_ON && url.pathname !== '/stats' && !/^\/(assets|favicon\.ico)/.test(url.pathname)) {
    const lvTag = (url.pathname === '/check' || url.pathname === '/hint') ? lv : 0;
    recordVisit(vid, ip, req, lvTag, url.pathname);
  }

  /* 登录校验 */
  if (url.pathname === '/check') {
    const u = maybeB64(url.searchParams.get('username') || '');
    const p = maybeB64(url.searchParams.get('password') || '');

    if (u === '' || p === '') {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Input your username and password');
    }

    const r = login(lv, u, p);
    if (r.kind !== 'success') bumpFail(ip, lv);

    // 真的拿到 flag 才算通关（诱饵不算）；第一关登录成功就算过
    if (r.kind === 'success') {
      const v = VISITS.get(vid);
      if (v) {
        if (lv === 1) {
          v.solved.add(1);
          appendLog({ t: Date.now(), v: vid, s: 1 });
        } else {
          const hit = (r.row || []).find((x) => typeof x === 'string' && x.indexOf('flag{') !== -1);
          if (hit && hit === FLAGS[lv]) { v.solved.add(lv); appendLog({ t: Date.now(), v: vid, s: lv }); }
        }
      }
    }

    // 静默关：三态同页，只有时间不同
    if (LEVELS[lv].echo === 'silent') {
      const delay = Math.min(r.sleep || 0, 5000);
      const body = pageSilent();
      const send = () => html(res, body);
      return delay > 0 ? setTimeout(send, delay) : send();
    }

    const q = pickQuip(lv, u, p, r.kind, r.row);
    const body = r.kind === 'error' ? pageError(lv, q)
      : r.kind === 'wrong' ? pageWrong(lv, q)
        : pageSuccess(lv, r.row, q);
    return html(res, body);
  }

  /* 交 flag */
  if (url.pathname === '/submit') {
    const flag = (url.searchParams.get('flag') || '').trim();
    const name = (url.searchParams.get('name') || '').trim().slice(0, 24) || 'anonymous';
    const ok = flag === FLAGS[lv];
    if (ok) {
      const used = SUBMIT_BY_IP.get(ip) || 0;
      if (used >= SUBMIT_MAX_PER_IP) {
        return html(res, pageTooMany(), 429);
      }
      SUBMIT_BY_IP.set(ip, used + 1);
      upsertScore(name, lv);
      solvedLevels.add(lv);
      saveScore();
    }
    return html(res, pageSubmit(ok, lv));
  }

  /* 计分板 */
  if (url.pathname === '/score') return html(res, pageScore());
  // 管理接口：容器内默认关闭（ENABLE_ADMIN=1 才开），别把后门递给选手
  if (!ADMIN_ON && (url.pathname === '/addscore' || url.pathname === '/reset'
    || url.pathname === '/export' || url.pathname === '/stats')) {
    return html(res, 'nothing here', 404);
  }

  if (url.pathname === '/addscore') {
    if (url.searchParams.get('key') !== STATS_KEY) return html(res, 'nothing here', 404);
    const name = (url.searchParams.get('name') || '').trim().slice(0, 24) || 'anonymous';
    const lv = parseInt(url.searchParams.get('lv') || '0', 10);
    const at = (url.searchParams.get('at') || '').trim() || fmtTs(Date.now());
    if (!LEVELS[lv]) return html(res, 'bad level', 400);
    upsertScore(name, lv, at);
    solvedLevels.add(lv);
    saveScore();
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(`ok, ${scoreboard.length} entries\n`);
  }
  if (url.pathname === '/reset') {
    if (url.searchParams.get('key') !== STATS_KEY) return html(res, 'nothing here', 404);
    try { fs.writeFileSync(LOG_FILE, ''); } catch (_) {}
    VISITS.clear();
    DAY_HITS.clear();
    TOTAL_HITS = 0;
    if (url.searchParams.get('all') === '1') clearScore();
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('visits cleared\n');
  }
  if (url.pathname === '/export') {
    if (url.searchParams.get('key') !== STATS_KEY) return html(res, 'nothing here', 404);
    let body = '';
    try { body = fs.readFileSync(LOG_FILE, 'utf8'); } catch (_) {}
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(body);
  }
  if (url.pathname === '/stats') {
    const k = url.searchParams.get('key') || '';
    return html(res, pageStats(k, url.searchParams.get('full') === '1'), k === STATS_KEY ? 200 : 404);
  }

  /* 提示 */
  if (url.pathname === '/hint') {
    const n = fails.get(`${ip}|${lv}`) || 0;
    const list = HINTS[lv] || [];
    const out = list.map((t, i) => ({ i: i + 1, need: lv <= 2 ? 0 : 8 * (i + 1), text: hintUnlocked(lv, i, ip) ? t : null }));
    const body = shell('Hint', `
    <div class="shout" style="font-size:38px;width:600px">就到此为止了吗，<br>你不是解的很快吗，<br>解起来！！</div>
    <div class="card" style="width:600px">
      <img class="hintgirl" src="/assets/hint-girl.jpg" alt="">
      <span class="pill">HINT · L${lv}</span>
      <h1 style="font-size:24px">${esc(LEVELS[lv].name)}</h1>
      <p class="note" style="margin:0 0 16px">你这一关已经失败 ${n} 次。${lv <= 2 ? '前两关是教学关，提示全开。' : '失败次数越多，解锁得越多。'}</p>
      ${out.map((h) => h.text
        ? `<p class="line" style="font-size:14px;margin:10px 0;line-height:1.85"><b style="color:${LEVELS[lv].accent}">#${h.i}</b> ${esc(h.text)}</p>`
        : `<p class="line" style="font-size:13px;margin:10px 0;color:#5D6B7A">#${h.i} 再失败 ${h.need - n} 次解锁</p>`).join('')}
      <p class="note"><a href="/?lv=${lv}">← 继续</a></p>
    </div>`, LEVELS[lv].accent, 'hint-bg.jpg');
    return html(res, body);
  }

  /* 解法（有人交过才开） */
  if (url.pathname === '/writeup') {
    const w = WRITEUPS[lv];
    if (!solvedLevels.has(lv)) {
      return html(res, shell('Writeup', `
      <div class="card"><span class="pill" style="background:#2A1315;color:#F87171;border-color:#5A2228">LOCKED</span>
      <h1 style="font-size:26px">还没解开</h1>
      <p class="line" style="font-size:14px;color:#A08A8E">这一关还没有人交出正确 flag，解法页锁着。</p>
      <p class="note"><a href="/?lv=${lv}">← 继续</a></p></div>`, '#F87171'));
    }
    return html(res, shell('Writeup', `
    <div class="card" style="width:640px"><span class="pill">WRITEUP · L${lv}</span>
    <h1 style="font-size:24px">${esc(w.title)}</h1>
    <p class="line" style="font-size:14px;line-height:1.9;color:#C9D6E4">${w.body}</p>
    <p class="note"><a href="/?lv=${lv}">← 继续</a> · <a href="/score">计分板</a></p></div>`, LEVELS[lv].accent));
  }

  /* 首页 */
  if (url.pathname === '/') return html(res, renderIndex(lv));

  /* 静态资源 */
  const rel = url.pathname.replace(/^\/+/, '');
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end('forbidden');
  }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'text/html; charset=utf-8' });
    res.end(buf);
  });
});

process.on('uncaughtException', (e) => console.error('UNCAUGHT', e && e.stack || e));
process.on('unhandledRejection', (e) => console.error('REJECT', e && e.stack || e));

initSqlJs({ locateFile: (f) => path.join(__dirname, 'node_modules/sql.js/dist', f) })
  .then((sql) => {
    console.log('sql.js ready');
    SQL = sql;
    seedAll();
    const restored = loadLog();
    if (restored) console.log(`restored ${restored} visit records`);
    const sc = loadScore();
    if (sc) console.log(`restored ${sc} scoreboard entries`);
    console.log('seed done');
    INDEX_TPL = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
    setInterval(seedAll, 30 * 60 * 1000).unref();
    server.listen(PORT, '0.0.0.0', () => console.log(`sqli-challenge on 0.0.0.0:${PORT}`));
  })
  .catch((e) => { console.error('init failed', e && e.stack || e); process.exit(1); });
