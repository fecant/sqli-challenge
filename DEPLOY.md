# 部署到 CTF 平台（动态题 / 一关一容器）

这份文档是把 SQL 注入靶改成 CTF 平台「动态题」的落地步骤。目标：四道题、四个独立容器、各自独立的动态 flag。

---

## 一、运行模式

服务通过环境变量决定跑成什么样，不需要改代码。

| 环境变量 | 取值 | 效果 |
|---|---|---|
| `LEVEL` | `1` / `2` / `3` / `4` | 单关卡模式。只开这一关，访问其他关返回 404 |
| `LEVEL` | 不设 | 四关全开（本地自用 / 分享链接） |
| `CTF_FLAG` | 任意字符串 | 本关的 flag，覆盖内置默认值 |
| `ENABLE_ADMIN` | `1` / `0` | `/stats` `/export` `/reset` `/addscore` 开关 |

**flag 环境变量按以下优先级依次读取**（平台用哪个名字都能接住）：

```
CTF_FLAG → GZCTF_FLAG → FLAG → DASCTF_FLAG → CTF_PLUS_FLAG → CHALLENGE_FLAG → FLAG_1..4
```

都没设则回落到内置默认 flag，仅供本地跑通流程。

**管理接口默认策略：**

- 单关卡模式（`LEVEL` 已设）→ 默认**关闭**
- 全关模式（不设 `LEVEL`）→ 默认**开启**

要强制覆盖就显式设 `ENABLE_ADMIN=1` 或 `0`。

---

## 二、本地验证

```bash
# 跑第三关，flag 注入成测试值
LEVEL=3 CTF_FLAG='flag{test_l3}' node server.js

# 另开一个终端
curl "http://127.0.0.1:3000/check?lv=3&username=flag'%2F%2A%2A%2Fand%2F%2A%2A%2Fsubstr(password,1,1)=char(102)%2F%2A%2A%2F%23&password=x"
# 预期：Login Success（第 1 位是 f）
```

要同时验证四关，就起四个终端各跑一个 `LEVEL`。

---

## 三、构建与推送（GitHub Actions）

已内置 `.github/workflows/docker-publish.yml`：推 `v*` tag 自动构建并推送 `linux/amd64` 镜像。

**1. 仓库准备**

```bash
cd sqli-challenge
git init
git add .
git commit -m "SQL injection challenge, one level per container"
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

**2. 在 GitHub 仓库里配 Secrets**

Settings → Secrets and variables → Actions → New repository secret：

| 名称 | 值 |
|---|---|
| `DOCKERHUB_USERNAME` | 你的 Docker Hub 用户名（本例 `Intanoste`） |
| `DOCKERHUB_TOKEN` | Docker Hub 的 Personal Access Token（不是登录密码） |

PAT 创建位置：Docker Hub → Account settings → Personal access tokens → New token，权限给 `Read & Write`。

**3. 触发构建**

```bash
git tag v1.0.0
git push origin v1.0.0
```

Actions 跑完后，镜像就是 `intanoste/sqli-challenge:v1.0.0` 和 `:latest`。

> 推送会自动创建仓库，不需要先在 Docker Hub 网页点 Create Repository。
> 镜像默认是 Public，CTF 平台才能拉取。

---

## 四、CTF 平台配置（每题填一遍）

| 字段 | L1 | L2 | L3 | L4 |
|---|---|---|---|---|
| 题目标题 | 第一关 · 深渊回望 | 第二关 · 偶像的黄昏 | 第三关 · 永恒轮回 | 第四关 · 上帝已死 |
| 题目类型 | ctf-动态题目 | 同左 | 同左 | 同左 |
| 镜像 tag | `intanoste/sqli-challenge:latest` | 同左 | 同左 | 同左 |
| 静态答案 | **关闭** | 关闭 | 关闭 | 关闭 |
| http 端口号 | `3000` | `3000` | `3000` | `3000` |
| 额外环境变量 | `{"LEVEL":"1"}` | `{"LEVEL":"2"}` | `{"LEVEL":"3"}` | `{"LEVEL":"4"}` |

**flag 不用填**，平台会自动注入到环境变量，服务读到后写进题库里：

| 关 | flag 放在哪 |
|---|---|
| L1 | 登录成功页直接显示 |
| L2 | `l2_secret_9f3` 表（诱饵 `l2_decoy_77` 里的 `flag{you_wish_this_was_it}` 是假的，会一直保留） |
| L3 | `b4bsql` 表中 `flag` 用户行的 password 列，用盲注逐位爆 |
| L4 | 同 L3，但三种结果同页，只能靠时间信道 |

**题目描述**用 Markdown，每题写对应那一章的故事 + 图片；图片需先传到平台或图床。

---

## 五、已经砍掉的东西（容器里不要有）

| 接口 | 为什么不给 |
|---|---|
| `/reset` | 能清空计分板和日志 |
| `/addscore` | 能伪造任意名字上榜单 |
| `/export` | 能导出全部访问日志 |
| `/stats` | 暴露所有访问者 IP |

这些在单关卡容器里默认 404。本地全关模式下仍可开，便于你自己看数据。

---

## 六、已知风险

- **Docker Hub 免费账号拉取限速**：匿名拉取按 IP 计 100 次 / 6 小时。正式比赛如果同时拉几百个容器会失败，需要提前跟平台确认有预热或镜像缓存。
- **镜像架构**：CI 里固定 `linux/amd64`。如果换成别的方式构建，记得 `--platform linux/amd64`。
- **flag 注入变量名**：本服务已经兼容常见 10 个变量名。如果平台用的是没见过的名字，在 `server.js` 的 `INJECTED_FLAG` 那一行加上即可。
- **管理接口的 key 是弱口令**（`shen7yin`），仓库公开前请用环境变量 `STATS_KEY` 覆盖掉，或直接删掉那四个路由。容器里默认关掉，但本地全关模式会开着。
- **每队一个独立容器**，各队互不可见，也没法共享计分板——这是动态题的架构特性，平台自己的排行榜会记成绩。

---

## 七、题面模板

每题的题目描述可以直接用下面这段改：

```markdown
## 城门

从前有个勇者，走了很远的路，站在城堡门口。门上写着：欢迎光临。他不信。
他在门口站了三天，等一个陷阱。第四天他推了一下门，门开了——没有锁，从来就没有锁。

### 目标

登录任意用户，拿到本关的 flag。

### 提示（按顺序解锁）

1. 你的输入已经长在 SQL 语句里了。
2. 注释掉后面那半句。
3. 闭合单引号，然后把剩下的干掉。
```

第三关、第四关的题面要写清楚：**没有回显、只能靠时间和布尔两种信道**。