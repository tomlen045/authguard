#!/usr/bin/env python3
"""authguard v1.0.0 — 登录安全哨兵：sshd 日志暴破定位+首次告警+BREACH得手判定+封禁建议。零依赖单文件 CLI。"""
import argparse
import datetime
import json
import os
import re
import sys

VERSION = '1.0.0'
EXIT_OK = 0
EXIT_SUSPECT_FOUND = 1
EXIT_BREACH = 2
EXIT_ENV_ERROR = 3

# ---- 不可变体系 I1: 平台源映射(只读，永不修改系统文件) ----
SOURCES = {
    'darwin': {
        'fail': [],  # macOS 无 faillog；用 log show 兜底(可选)
        'wtmp': '/var/log/wtmp',      # last 读
        'applog': '/var/log/system.log',
    },
    'linux': {
        'fail': ['/var/log/faillog', '/var/log/btmp'],
        'wtmp': '/var/log/wtmp',
        'secure': ['/var/log/secure', '/var/log/auth.log'],
    },
}


def now_local():
    return datetime.datetime.now().astimezone()


def parse_secure_time(line, year=None):
    """sshd 日志两种时间头: 'Oct  7 09:15:01' / '2026-10-07T09:15:01.123+08:00'"""
    m = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})', line)
    if m:
        mon_map = {m2: i for i, m2 in enumerate(
            ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
        y = year or now_local().year
        try:
            return datetime.datetime(
                y, mon_map[m.group(1)], int(m.group(2)),
                *map(int, m.group(3).split(':'))).astimezone()
        except ValueError:
            return None
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', line)
    if m:
        try:
            return datetime.datetime(*map(int, m.groups())).astimezone()
        except ValueError:
            return None
    return None


# ---- 事件抽取(不变量 I2: 每条事件必须带 时间/来源IP/用户/结果 四元组) ----
RE_SSHD_FAIL = re.compile(
    r'(?P<srv>sshd(?:\[\d+\])?)?:?\s*(?:Failed|Invalid user|Connection closed by authenticating user|'
    r'error: maximum authentication attempts exceeded).*?(?:from|user)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
    re.I)
RE_USER = re.compile(r'(?:user|invalid user)\s+(\S+)')
RE_SSHD_OK = re.compile(r'[Aa]ccepted\s+\S+\s+for\s+(?P<user>\S+).*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})')


def parse_auth_log(path, year=None):
    """从 secure/auth.log 抽四元组事件。保证只读。"""
    events = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if 'sshd' not in line:
                    continue
                t = parse_secure_time(line, year)
                if t is None:
                    continue
                m = RE_SSHD_OK.search(line)
                if m:
                    events.append({'t': t, 'ip': m.group('ip'), 'user': m.group('user'), 'ok': True, 'src': os.path.basename(path)})
                    continue
                mf = RE_SSHD_FAIL.search(line)
                if mf:
                    mu = RE_USER.search(line)
                    events.append({'t': t, 'ip': mf.group('ip'), 'user': mu.group(1) if mu else '?', 'ok': False, 'src': os.path.basename(path)})
    except OSError:
        pass
    return events


# ---- 阈值(不变量 I3: 阈值显式参数，可覆盖，默认 5 次/10 分钟) ----
DEFAULT_FAIL_N = 5
DEFAULT_WIN_MIN = 10


def window_bursts(events, fail_n, win_min, exclude_users=()):
    """滑动窗口暴破定位：同一 IP 在窗口内失败 >= fail_n。
    返回 [{ip, count, first, last, users}] 按 count 降序。"""
    fails = [e for e in events if not e['ok'] and e['user'] not in exclude_users]
    by_ip = {}
    for e in fails:
        by_ip.setdefault(e['ip'], []).append(e)
    bursts = []
    win = datetime.timedelta(minutes=win_min)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x['t'])
        best = None
        j = 0
        for i in range(len(evs)):
            # 指针 j 只前进：窗口左界单调右移
            while evs[i]['t'] - evs[j]['t'] > win:
                j += 1
            cnt = i - j + 1
            if cnt >= fail_n and (best is None or cnt > best['count']):
                best = {'ip': ip, 'count': cnt, 'first': evs[j]['t'], 'last': evs[i]['t'],
                        'users': sorted({e['user'] for e in evs[j:i + 1]})}
        if best:
            bursts.append(best)
    bursts.sort(key=lambda b: (-b['count'], b['ip']))
    return bursts


def first_seen(events, ip, state_path):
    """首次告警(不变量 I4: 基于持久化状态，重复运行不重复轰炸)。"""
    try:
        with open(state_path, encoding='utf-8') as f:
            seen = json.load(f)
    except (OSError, ValueError):
        seen = {}
    is_new = str(ip) not in seen
    return is_new, seen


def save_seen(state_path, ips):
    try:
        with open(state_path, encoding='utf-8') as f:
            seen = json.load(f)
    except (OSError, ValueError):
        seen = {}
    for ip in ips:
        seen[str(ip)] = now_local().isoformat(timespec='seconds')
    tmp = state_path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(seen, f, ensure_ascii=False, indent=1)
    os.replace(tmp, state_path)


def accepted_from(events, ip, since=None):
    """该 IP 的成功登录。since 给定时只计暴破窗口开始之后的(时间维度定罪:
    窗口前的正常登录不算得手证据)。"""
    return [e for e in events if e['ok'] and e['ip'] == ip and (since is None or e['t'] >= since)]


def suggest_ban(ip, daemon=None):
    """封禁建议(不变量 I5: 只建议不执行——默认绝不改系统防火墙)。"""
    if sys.platform == 'darwin':
        return (f'echo "block drop from {ip} to any" | sudo pfctl -ef -  # 或落地到 /etc/pf.anchors')
    return (f'sudo ufw insert 1 deny from {ip}  # 或: sudo iptables -I INPUT -s {ip} -j DROP')


# ---- 报告 ----
def fmt_t(dt):
    return dt.strftime('%m-%d %H:%M:%S')


def cmd_check(args):
    src = SOURCES.get('linux' if sys.platform.startswith('linux') else 'darwin', {})
    events = []
    logs = []
    if args.log:
        logs = list(args.log)
    else:
        logs = src.get('secure', []) + ([args.file] if args.file else [])
    for p in logs:
        evs = parse_auth_log(p, year=args.year)
        events.extend(evs)
    if args.file and not args.log:
        events.extend(parse_auth_log(args.file, year=args.year))
    if not events and not args.log and not args.file:
        print('[!] 未找到 sshd 日志源（macOS 请用 --file 指定导出日志，或 --log 直接给路径）', file=sys.stderr)
        return EXIT_ENV_ERROR

    bursts = window_bursts(events, args.fail_n, args.win, exclude_users=tuple(args.ignore or ()))
    state = args.state
    verdict_lines = []
    worst = bursts[0] if bursts else None
    exit_code = EXIT_OK

    print(f'authguard v{VERSION} · 登录安全哨兵')
    print(f'事件 {len(events)} 条(成功 {sum(1 for e in events if e["ok"])} / 失败 {sum(1 for e in events if not e["ok"])}) · 窗口 {args.win}min · 阈值 {args.fail_n} 次')
    print('-' * 62)

    new_ips = []
    for b in bursts:
        is_new, seen = first_seen(events, b['ip'], state)
        acc = accepted_from(events, b['ip'], since=b['first'])
        breach = bool(acc)
        tag = 'BREACH' if breach else ('NEW' if is_new else 'known')
        icon = '!!' if breach else (' + ' if is_new else '   ')
        print(f'[{icon}] {b["ip"]}  失败 {b["count"]} 次  {fmt_t(b["first"])} → {fmt_t(b["last"])}')
        print(f'     用户: {", ".join(b["users"][:6])}{" ..." if len(b["users"]) > 6 else ""}'
              f'  成功登录 {len(acc)} 次  [{tag}{" 首见" if is_new else ""}]')
        if breach:
            verdict_lines.append(f'BREACH {b["ip"]}: 暴破后成功登录 {len(acc)} 次 @ {fmt_t(acc[-1]["t"])} 用户 {acc[-1]["user"]}')
            exit_code = EXIT_BREACH
        elif exit_code < EXIT_SUSPECT_FOUND:
            exit_code = EXIT_SUSPECT_FOUND
        if is_new:
            new_ips.append(b['ip'])
    if not bursts:
        print('未见窗口暴破。基线正常。')

    if verdict_lines:
        print('-' * 62)
        for v in verdict_lines:
            print('判定: ' + v)
    if new_ips and worst and not verdict_lines:
        print('-' * 62)
        print('封禁建议(只建议，不执行):')
        print('  ' + suggest_ban(worst['ip']))
    if new_ips:
        save_seen(state, new_ips)
    return exit_code


def cmd_report(args):
    """JSON 机器可读输出(供 cron/监控管道消费)。"""
    src = SOURCES.get('linux' if sys.platform.startswith('linux') else 'darwin', {})
    logs = list(args.log) if args.log else src.get('secure', [])
    events = []
    for p in logs:
        events.extend(parse_auth_log(p, year=args.year))
    bursts = window_bursts(events, args.fail_n, args.win)
    burst_json = [
        {'ip': b['ip'], 'count': b['count'],
         'first': b['first'].isoformat(timespec='seconds'),
         'last': b['last'].isoformat(timespec='seconds'),
         'users': b['users'],
         'accepted_after': sum(1 for e in events if e['ok'] and e['ip'] == b['ip'])}
        for b in bursts]
    out = {
        'tool': 'authguard', 'version': VERSION,
        'generated_at': now_local().isoformat(timespec='seconds'),
        'events_total': len(events),
        'events_ok': sum(1 for e in events if e['ok']),
        'events_fail': sum(1 for e in events if not e['ok']),
        'window_min': args.win, 'threshold': args.fail_n,
        'bursts': burst_json,
        'exit_hint': 'breach' if any(b['accepted_after'] for b in burst_json) else ('suspect' if burst_json else 'ok'),
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def cmd_ban(args):
    print(suggest_ban(args.ip))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog='authguard', description='登录安全哨兵: 暴破定位/首次告警/BREACH 判定。零依赖单文件。')
    ap.add_argument('--version', action='version', version=f'authguard {VERSION}')
    sub = ap.add_subparsers(dest='cmd')

    c = sub.add_parser('check', help='体检: 聚合 sshd 失败事件, 定位暴破')
    c.add_argument('--fail-n', type=int, default=DEFAULT_FAIL_N, help=f'窗口内失败阈值 (默认 {DEFAULT_FAIL_N})')
    c.add_argument('--win', type=int, default=DEFAULT_WIN_MIN, help='滑动窗口分钟 (默认 10)')
    c.add_argument('--log', action='append', help='auth 日志路径, 可多次')
    c.add_argument('--file', help='附加日志文件(macOS 用)')
    c.add_argument('--state', default=os.path.expanduser('~/.authguard_state.json'), help='首次告警状态文件')
    c.add_argument('--ignore', action='append', help='忽略的用户名, 可多次')
    c.add_argument('--year', type=int, default=None, help='syslog 无年份, 手工指定')
    c.set_defaults(fn=cmd_check)

    r = sub.add_parser('report', help='JSON 报告(管道友好)')
    r.add_argument('--fail-n', type=int, default=DEFAULT_FAIL_N)
    r.add_argument('--win', type=int, default=DEFAULT_WIN_MIN)
    r.add_argument('--log', action='append')
    r.add_argument('--year', type=int, default=None)
    r.set_defaults(fn=cmd_report)

    b = sub.add_parser('ban', help='输出对某 IP 的封禁建议命令(不执行)')
    b.add_argument('ip')
    b.set_defaults(fn=cmd_ban)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, 'fn', None):
        ap.print_help()
        return EXIT_OK
    return args.fn(args)


if __name__ == '__main__':
    sys.exit(main())
