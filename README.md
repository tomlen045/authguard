# authguard 🔐

**登录安全哨兵** —— 半夜被告警叫醒，十有八九是三件事：配置被人改了（[cfgdrift](https://github.com/tomlen045/cfgdrift) 管）、磁盘爆了（[capguard](https://github.com/tomlen045/capguard) 管）、**有人在你家门口试密码（authguard 管）**。

authguard 聚合 sshd 认证日志：**暴破定位 → 首次告警 → 得手判定（BREACH）→ 一键封禁建议**。退出码即结论，挂 cron 就是一条登录安全哨兵防线。

[![tests](https://img.shields.io/badge/self--tests-18%2F18-green)]() [![slowscan](https://img.shields.io/badge/slow--scan--scene-9%2F9-green)]() [![deps](https://img.shields.io/badge/deps-zero-yellow)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

[English](README_EN.md) | 简体中文

---

## 解决什么问题

* 「被暴力破解了吗？」答不上来 → **窗口暴破定位：同一 IP 在 10 分钟内失败 ≥5 次，连击从几点几分到几点几分、试了哪些用户名，一张表说完**
* 暴破 IP 今天报一次明天又报一次，告警疲劳 → **首次告警机制：新 IP 才提醒，见过的 IP 归为 known 持续跟踪，不再重复轰炸**
* 最怕的不是被试密码，是**被试成了** → **BREACH 判定：暴破窗口之后出现成功登录 = 得手，退出码直接给 2**，监控管道拿退出码就能触发应急
* 拿着日志不知道该封谁 → **`ban` 子命令直接给出当前平台的封禁命令文本（ufw/iptables/pfctl），只建议、不执行——按下去的手是你的**
* 定时低频慢扫（每 8 分钟一次这种）默认阈值抓不到 → **`--win`/`--fail-n` 手动兜底参数**，60 分钟窗 6 次阈值照样定罪（自带慢扫场景演示）

## 30 秒上手

```bash
# 体检（macOS 用 --file 给日志；Linux 自动找 /var/log/secure、/var/log/auth.log）
python3 authguard.py check --file /path/to/auth.log

# 慢扫场景：放宽窗口 + 降阈值
python3 authguard.py check --file auth.log --win 60 --fail-n 6

# JSON 报告（cron / 监控管道友好）
python3 authguard.py report --file auth.log

# 封禁建议（只打印命令，不执行）
python3 authguard.py ban 203.0.113.66
```

### 退出码语义（管道即结论）

| 退出码 | 含义 |
|---|---|
| 0 | 基线正常，未见窗口暴破 |
| 1 | SUSPECT：有暴破 IP，暂无得手证据 |
| 2 | **BREACH：暴破窗口之后出现成功登录** |
| 3 | 环境错误（找不到日志源） |

## 真实输出长什么样

```text
authguard v1.0.0 · 登录安全哨兵
事件 340 条(成功 301 / 失败 39) · 窗口 10min · 阈值 5 次
--------------------------------------------------------------
[ + ] 203.0.113.66  失败 25 次  10-07 02:00:00 → 10-07 02:09:59
     用户: admin  成功登录 0 次  [NEW 首见]
[!!] 198.51.100.23  失败 8 次  10-07 00:52:00 → 10-07 00:59:00
     用户: ?  成功登录 1 次  [BREACH 首见]
--------------------------------------------------------------
判定: BREACH 198.51.100.23: 暴破后成功登录 1 次 @ 10-07 01:00:00 用户 root
```

## 设计不变量（为什么可信）

1. **只读**：对所有日志文件只读，永不修改系统任何文件；唯一写操作是自己的状态文件（`~/.authguard_state.json`，先写临时文件再 `os.replace` 原子落盘）
2. **四元组完整性**：每条事件必须带 时间/来源IP/用户/结果，解析不出时间的事件直接丢弃，绝不含糊入库
3. **阈值显式**：`--fail-n`/`--win` 显式参数可覆盖，默认 5 次/10 分钟写死在 `--help` 里，无隐藏默认
4. **首次告警**：新 IP 才算 NEW，重复运行不重复轰炸；状态可随时删掉重置
5. **只建议不执行**：`ban` 输出命令文本，防火墙永远不由工具代按
6. **时间维度定罪**：暴破窗口**之前**的正常登录不构成得手证据，`since` 语义防误判

## 真实偏态自测

检测类工具最怕「合成均匀数据自测全绿、实战检不出」。authguard 的自测 fixture 是偏态的：**1 个 25 连击暴破 IP + 1 个得手 BREACH IP + 1 个 300 次正常登录的噪音用户 + 1 个低于阈值的 4 连击 IP**——正常流量占绝对多数，异常是少数。18 项自测 + 9 项慢扫场景演示全绿。

```bash
python3 selftest.py        # 18 项
python3 demo_slowscan.py   # 慢扫场景 9 项
```

## 哨兵套件

| 工具 | 管什么 |
|---|---|
| [cronguard](https://github.com/tomlen045/cronguard) | 定时任务死活 |
| [cfgdrift](https://github.com/tomlen045/cfgdrift) | 谁动了配置 |
| [capguard](https://github.com/tomlen045/capguard) | 磁盘水位与走势 |
| [logwhisperer](https://github.com/tomlen/logwhisperer) | 日志考古三件套 |
| **authguard** | **谁在门口试密码** |
| [porteye](https://github.com/tomlen045/porteye) | 端口暴露面 |
| [certlens](https://github.com/tomlen045/certlens) | 证书体检 |
| [linkpulse](https://github.com/tomlen045/linkpulse) | 发布物死活巡检 |

## License

MIT
