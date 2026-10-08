# authguard 🔐

**Login security sentinel** — woken at 3am, it's usually one of three things: config drifted ([cfgdrift](https://github.com/tomlen045/cfgdrift)), disk filling up ([capguard](https://github.com/tomlen045/capguard)), or **someone guessing passwords at your front door (authguard)**.

authguard aggregates sshd auth logs: **brute-force localization → first-seen alerts → breach verdict → one-line ban suggestion**. Exit codes are the verdict — drop it into cron and you have a standing auth-security sentinel.

[![tests](https://img.shields.io/badge/self--tests-18%2F18-green)]() [![slowscan](https://img.shields.io/badge/slow--scan--scene-9%2F9-green)]() [![deps](https://img.shields.io/badge/deps-zero-yellow)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

简体中文 | [English](README_EN.md)

---

## What problem does it solve

* "Are we being brute-forced?" — you can't answer → **window burst localization: same IP failing ≥5 times in 10 minutes, with exact first/last timestamps and usernames tried, in one table**
* The same attacker IP re-alerts every day → **first-seen alerting**: only new IPs alert; known IPs stay tracked without repeated noise
* The scary part isn't the guessing, it's the **success** → **BREACH verdict: a successful login after the burst window = breach = exit code 2**, ready for pipelines
* You have logs but don't know what to ban → **`ban` subcommand prints the exact command for your platform (ufw/iptables/pfctl) — suggests, never executes**
* Slow scans (one try every 8 minutes) slip under default thresholds → **`--win` / `--fail-n` manual fallback parameters** catch them (dedicated slow-scan demo included)

## 30-second start

```bash
# Checkup (macOS: pass --file; Linux auto-detects /var/log/secure, /var/log/auth.log)
python3 authguard.py check --file /path/to/auth.log

# Slow-scan scenario: widen window + lower threshold
python3 authguard.py check --file auth.log --win 60 --fail-n 6

# JSON report (cron / pipeline friendly)
python3 authguard.py report --file auth.log

# Ban suggestion (prints only, never executes)
python3 authguard.py ban 203.0.113.66
```

### Exit codes (the pipeline is the verdict)

| Code | Meaning |
|---|---|
| 0 | Baseline normal, no window bursts |
| 1 | SUSPECT: burst IP present, no evidence of success |
| 2 | **BREACH: successful login after the burst window** |
| 3 | Environment error (no log source found) |

## Sample output

```text
authguard v1.0.0 · login security sentinel
events 340 (ok 301 / fail 39) · window 10min · threshold 5
--------------------------------------------------------------
[ + ] 203.0.113.66  25 fails  10-07 02:00:00 → 10-07 02:09:59
     users: admin  accepted 0  [NEW]
[!!] 198.51.100.23  8 fails  10-07 00:52:00 → 10-07 00:59:00
     users: ?  accepted 1  [BREACH]
--------------------------------------------------------------
verdict: BREACH 198.51.100.23: accepted login after burst @ 10-07 01:00:00 user root
```

## Design invariants (why it's trustworthy)

1. **Read-only**: never modifies any system file; the only write is its own state file (`~/.authguard_state.json`, atomic via tmp + `os.replace`)
2. **Tuple integrity**: every event carries time/IP/user/result; unparseable events are dropped, never half-stored
3. **Explicit thresholds**: `--fail-n`/`--win` overridable; defaults (5 fails / 10 min) documented in `--help`, nothing hidden
4. **First-seen alerting**: new IP = NEW, repeats = known; delete the state file to reset
5. **Suggest, never execute**: `ban` prints text; your hand presses the key
6. **Time-dimensioned verdict**: logins *before* the burst window are not evidence of success (`since` semantics)

## Skewed-fixture self-tests

Detection tools die from "uniform synthetic data passes tests, real incidents slip through". authguard's fixture is skewed: **one 25-burst IP + one BREACH IP + one 300-login legit user + one below-threshold IP** — normal traffic dominates, anomalies are the minority. 18 self-tests + 9 slow-scan scenario checks, all green.

```bash
python3 selftest.py        # 18 checks
python3 demo_slowscan.py   # 9 slow-scan checks
```

## The sentinel suite

| Tool | Watches |
|---|---|
| [cronguard](https://github.com/tomlen045/cronguard) | cron jobs alive |
| [cfgdrift](https://github.com/tomlen045/cfgdrift) | who touched config |
| [capguard](https://github.com/tomlen045/capguard) | disk level & trend |
| [logwhisperer](https://github.com/tomlen/logwhisperer) | log archaeology |
| **authguard** | **who's knocking at the door** |
| [porteye](https://github.com/tomlen045/porteye) | exposed ports |
| [certlens](https://github.com/tomlen045/certlens) | cert health |
| [linkpulse](https://github.com/tomlen045/linkpulse) | published-link patrol |

## License

MIT
