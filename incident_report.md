# Brute Force Investigation

## Executive Summary

- **Generated**: 2026-04-23 12:29:45
- **Total Events**: 51
- **Critical Events**: 0
- **High Severity Events**: 1
- **Medium Severity Events**: 50

## Affected Assets

- **Unique Source IPs**: 1
- **Unique Users**: 7
- **Host**: sshd

## Threat Intelligence

| IP Address | Type | Severity | Reputation |
|----------|------|----------|------------|
| 185.220.101.45 | Tor Exit Node | high | malicious |


## Attack Correlations

### Brute Force Campaigns

- **185.220.101.45**: 40 failed attempts


## MITRE ATT&CK Tactics

**Detected Tactics**: 1

| Technique | Events | Description |
|-----------|--------|-------------|
| T1078 | 1 | Valid Accounts |


## Event Timeline

| Timestamp | Severity | Event Type | Source IP | User | Message |
|-----------|----------|-----------|-----------|------|---------|
| Apr 22 08:00:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | admin | Apr 22 08:00:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:00:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:00:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:00:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:00:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:00:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:00:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:00:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:00:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:01:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | root | Apr 22 08:01:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:01:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:01:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:01:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:01:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:01:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:01:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:01:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:01:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:02:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | backup | Apr 22 08:02:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:02:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:02:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:02:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:02:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:02:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:02:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:02:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:02:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:03:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | jsmith | Apr 22 08:03:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:03:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:03:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:03:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:03:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:03:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:03:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:03:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:03:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:04:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | deploy | Apr 22 08:04:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:04:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:04:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:04:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:04:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:04:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:04:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:04:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:04:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:05:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | admin | Apr 22 08:05:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:05:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:05:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:05:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:05:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:05:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:05:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:05:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:05:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:06:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | mwilson | Apr 22 08:06:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:06:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:06:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:06:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:06:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:06:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:06:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:06:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:06:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:07:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | mwilson | Apr 22 08:07:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:07:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:07:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:07:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:07:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:07:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:07:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:07:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:07:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:08:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | mwilson | Apr 22 08:08:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:08:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:08:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:08:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:08:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:08:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:08:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:08:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:08:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:09:00 | MEDIUM | ssh_invalid_user | 185.220.101.45 | ubuntu | Apr 22 08:09:00 localhost sshd[TACTIC:T1110]: Inva |
| Apr 22 08:09:12 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:09:12 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:09:24 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:09:24 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:09:36 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:09:36 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:09:48 | MEDIUM | ssh_login_fail | 185.220.101.45 |  | Apr 22 08:09:48 localhost sshd[TACTIC:T1078]: Fail |
| Apr 22 08:10:00 | **HIGH** | syslog | 185.220.101.45 | admin | Maximum authentication attempts exceeded for admin |


## Recommendations

1. **Immediate**: Block identified malicious IPs at perimeter firewall
2. **Short-term**: Reset credentials for compromised accounts
3. **Medium-term**: Review access logs and implement MFA
4. **Long-term**: Conduct full forensic investigation

---
*Report generated by LogSentry*
