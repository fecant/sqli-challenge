# 神隐の最終兵器 SQL 城堡

一个可公网分享的 SQL 注入练习靶：四级阶梯，每关只叠一种真实赛题里会出现的约束，且每关都可解。

内存 SQLite（`sql.js`）+ Node 原生 `http`，无文件系统依赖、无出站请求、单语句执行、输出做 HTML 转义，可以放心放在公网上。

## 镜像

```
ghcr.io/fecant/sqli-challenge:latest
```

推 `main` 自动构建（`build-and-push` workflow），带 GitHub Actions 层缓存，后续构建只需几十秒。

```bash
docker run -p 3000:3000 \
  -e LEVEL=1 \
  -e 'CTF_FLAG=flag{your_own_flag}' \
  ghcr.io/fecant/sqli-challenge:latest
```

打开 <http://127.0.0.1:3000/>。

## 四关

| 关 | 标题 | 只叠一种约束 | 解法方向 |
|---|---|---|---|
| L1 | 炒鸡结丹 | 无过滤 + 全回显 | 字符串闭合、注释 |
| L2 | 优异的婪 | 单次删词 + 全回显 | 双写绕过、`union` 数列、查 `sqlite_master` |
| L3 | 被诬陷晓 | 递归删词 + 去空格 + 无回显 | 双写失效，用 `/**/` 当空格，布尔盲注 |
| L4 | 晌抵在一吻 | 同 L3 过滤 + 三态同一响应 | 只有时间差可用：`sleep()` + `AND` 短路 |

每一关有独立的库实例，L2 拖库拖不到 L3/L4 的 flag。

## 环境变量

| 变量 | 取值 | 说明 |
|---|---|---|
| `LEVEL` | `1`~`4` | 单关卡模式，一个容器 = 一道题 = 一个 flag；不设则四关全开 |
| `CTF_FLAG` | 任意字符串 | 本关 flag，覆盖内置默认值（也兼容 `GZCTF_FLAG` / `FLAG` / `DASCTF_FLAG` / `CTF_PLUS_FLAG` / `CHALLENGE_FLAG` / `FLAG_1..4`） |
| `ENABLE_ADMIN` | `1` / `0` | `/stats` `/export` `/reset` `/addscore` 总开关；单关卡模式默认关，全关模式默认开 |

> 公开部署时如果跑全关模式，记得显式设 `ENABLE_ADMIN=0`，别把管理接口递给选手。

## 本地跑

```bash
npm install
node server.js
# 或指定关卡
LEVEL=3 CTF_FLAG='flag{test_l3}' node server.js
```

## 端点

| 路径 | 用途 |
|---|---|
| `/` | 关卡页（`?lv=1..4`） |
| `/check` | 登录校验点，注入目标 |
| `/hint` | 提示 |
| `/submit` | 交 flag |
| `/score` | 计分板（只显示名字/关卡/时间，不含 flag） |
| `/writeup` | 通关后解锁的解法页 |

## 部署到 CTF 平台

见 [DEPLOY.md](DEPLOY.md)：动态题一容器一关一 flag 的落地步骤。
