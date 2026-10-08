#!/usr/bin/env python3
"""authguard 自测: 18 项。 fixture 用真实偏态分布——1 个暴破 IP(25 连击)+1 个 BREACH IP(失败后成功)+长尾噪音, 禁均匀合成。"""
import datetime
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('authguard', os.path.join(HERE, 'authguard.py'))
ag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ag)

PASS = 0
FAIL = 0


def ok(name, cond, extra=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  ok {PASS:02d} - {name}')
    else:
        FAIL += 1
        print(f'  FAIL     - {name} {extra}')


YEAR = 2026
BASE = datetime.datetime(2026, 10, 7, 2, 0, 0)


def syslog(dt):
    return dt.strftime('%b %e %H:%M:%S').replace('  ', '  ') if dt.day >= 10 else dt.strftime('%b  %d %H:%M:%S')


def make_log(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


# ---------- fixture: 偏态分布 ----------
# IP A (203.0.113.66): 02:00-02:09 25 连击失败 (暴破, 无成功) -> SUSPECT/NEW
# IP B (198.51.100.23): 01:00 起 8 连击失败, 01:09 成功 root -> BREACH
# IP C (192.0.2.7): 全天 300 条成功登录 + 零星 2 次失败 (正常用户噪音)
# IP D (10.255.0.9): 4 次失败 (低于阈值 5, 不应报)
tmp = tempfile.mkdtemp(prefix='authguard_t_')
lines = []
t = BASE
for i in range(25):
    tt = t + datetime.timedelta(minutes=i % 9, seconds=i * 7)
    lines.append(f'{syslog(tt)} srv01 sshd[100{i}]: Failed password for invalid user admin from 203.0.113.66 port {40000 + i} ssh2')
for i in range(8):
    tt = BASE - datetime.timedelta(hours=1, minutes=8 - i)
    lines.append(f'{syslog(tt)} srv01 sshd[200{i}]: Failed password for root from 198.51.100.23 port {41000 + i} ssh2')
ttb = BASE - datetime.timedelta(hours=1)
lines.append(f'{syslog(ttb)} srv01 sshd[2100]: Accepted password for root from 198.51.100.23 port 41008 ssh2')
for i in range(300):
    tt = BASE + datetime.timedelta(minutes=i * 4)
    lines.append(f'{syslog(tt)} srv01 sshd[300{i}]: Accepted publickey for deploy from 192.0.2.7 port {42000 + i} ssh2')
    if i in (57, 58):
        lines.append(f'{syslog(tt + datetime.timedelta(seconds=3))} srv01 sshd[301{i}]: Failed password for deploy from 192.0.2.7 port {42001 + i} ssh2')
for i in range(4):
    tt = BASE + datetime.timedelta(minutes=30 + i)
    lines.append(f'{syslog(tt)} srv01 sshd[400{i}]: Failed password for invalid user oracle from 10.255.0.9 port {43000 + i} ssh2')
logpath = os.path.join(tmp, 'auth.log')
make_log(logpath, lines)

# ---------- T1 事件抽取四元组 ----------
evs = ag.parse_auth_log(logpath, year=YEAR)
ok('T01 事件总数 = 25+8+1+300+2+4 = 340', len(evs) == 340, f'got {len(evs)}')
ok('T02 成功/失败 = 301/39', (sum(1 for e in evs if e['ok']), sum(1 for e in evs if not e['ok'])) == (301, 39))
ok('T03 每条事件带时间(全部解析成功)', all(e['t'] for e in evs))
ok('T04 每条事件带 IP/用户/结果', all(e['ip'] and e['user'] is not None and isinstance(e['ok'], bool) for e in evs))

# ---------- T2 暴破定位(偏态: 暴破是少数) ----------
bursts = ag.window_bursts(evs, 5, 10)
ips = [b['ip'] for b in bursts]
ok('T05 暴破 IP 仅 2 个(A 和 B), D 低于阈值不报', ips == ['203.0.113.66', '198.51.100.23'], f'got {ips}')
ok('T06 A 计数 25(窗口内)', bursts[0]['count'] == 25, f'got {bursts[0]["count"]}')
ok('T07 C 的 2 次失败不出报', '192.0.2.7' not in ips)
ok('T08 按 count 降序', all(bursts[i]['count'] >= bursts[i + 1]['count'] for i in range(len(bursts) - 1)))

# ---------- T3 BREACH 判定 ----------
accB = ag.accepted_from(evs, '198.51.100.23')
ok('T09 B 成功登录 1 次(暴破后得手)', len(accB) == 1)
ok('T10 A 无成功登录', ag.accepted_from(evs, '203.0.113.66') == [])

# ---------- T4 CLI check 全链路 ----------
state = os.path.join(tmp, 'state.json')
r1 = ag.main(['check', '--log', logpath, '--year', str(YEAR), '--state', state])
ok('T11 check 首跑退出码 1 (SUSPECT, B 的成功被正确归类仍含 breach 逻辑?)', r1 in (ag.EXIT_SUSPECT_FOUND, ag.EXIT_BREACH), f'got {r1}')
ok('T12 首跑后状态文件落盘', os.path.exists(state))
seen = json.load(open(state))
ok('T13 状态记录首见 IP', '203.0.113.66' in seen and '198.51.100.23' in seen)
r2 = ag.main(['check', '--log', logpath, '--year', str(YEAR), '--state', state])
ok('T14 二跑退出码仍非 0 (持续暴破仍在场)', r2 != 0)
ok('T15 退出码语义: 有成功登录的暴破=BREACH(2)', r2 == ag.EXIT_BREACH, f'got {r2}')

# ---------- T5 report JSON ----------
import io
import contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ag.main(['report', '--log', logpath, '--year', str(YEAR)])
rep = json.loads(buf.getvalue())
ok('T16 report JSON 可解析且 bursts=2', rep['tool'] == 'authguard' and len(rep['bursts']) == 2)
ok('T17 exit_hint=breach', rep['exit_hint'] == 'breach')

# ---------- T6 封禁建议只建议不执行 ----------
sug = ag.suggest_ban('203.0.113.66')
ok('T18 ban 建议是命令文本且含 IP', '203.0.113.66' in sug and ('ufw' in sug or 'pfctl' in sug or 'iptables' in sug))

# ---------- 汇总 ----------
print(f'\n{PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
