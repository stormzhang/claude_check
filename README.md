# ip_check

A lightweight diagnostic tool for AI developers to verify network environment compatibility and IP reputation for LLM API access.

![screenshot](./claude-check.png)

[English](#english) | [中文](#中文)

---

## English

### Why

When using AI tools like Claude Code, OpenAI API, or Cursor, misconfigured network environments can lead to request failures, risk controls, or even account bans. Common issues include:

- **IPv6 leaking real location** — Most proxies only handle IPv4; IPv6 can expose your actual geographic location
- **DNS leakage** — Local DNS servers can reveal your true location to AI services
- **High-risk IP** — Datacenter IPs or abused IPs are more likely to trigger risk controls
- **Timezone mismatch** — Inconsistency between local timezone and IP geolocation increases anomaly detection probability

`ip_check` detects all these issues in one run, helping you verify your environment before using AI tools.

### Features

| Check Item | Description |
|------------|-------------|
| LAN IP / IPv6 | Detect local IP, verify if IPv6 is disabled |
| DNS Servers | Identify DNS origin (domestic/foreign), label known DNS providers |
| Public IP Info | Exit IP, country, region, ISP, organization |
| Proxy Detection | Env proxy settings, whether IP is flagged as proxy |
| IP Type | Residential vs. datacenter IP identification |
| IP Risk Score | Risk scoring via proxycheck.io |
| Abuse Records | IP abuse lookup via StopForumSpam |
| Timezone Consistency | Compare local CLI timezone with public IP geolocation timezone |

### Quick Start

```bash
python ip_check.py
```

Dependencies (`requests`, etc.) will be auto-detected and installed on first run.

#### Requirements

- Python 3.7+
- macOS / Linux / Windows

### Understanding the Results

**LAN & DNS** — Disable IPv6 if possible. Most proxies don't handle IPv6 traffic, which may expose two IPs from different regions simultaneously. If a domestic DNS is detected, adjust DNS settings in your proxy software.

**Public IP Info** — Shows your exit IP after proxy, including country/region, ISP, and timezone. These directly affect how AI services evaluate your request origin.

**IP Risk Assessment** — Identifies whether your IP is residential or datacenter. Datacenter IPs aren't necessarily problematic, but the tool will query risk scores and abuse records. Switch nodes if your risk score is high.

**Timezone Consistency** — Compares your local `$TZ` environment variable (or system timezone) with the public IP's timezone. Mismatches increase the probability of being flagged as anomalous. Set `TZ` in your shell config to match your IP's IANA timezone (e.g., `America/Los_Angeles`).

---

## 中文

### 为什么需要这个工具

使用 Claude Code、OpenAI API、Cursor 等 AI 工具时，网络环境配置不当可能导致请求失败、账号风控甚至封禁。常见问题包括：

- **IPv6 泄露真实地址** — 代理通常只处理 IPv4，IPv6 会暴露你的实际位置
- **DNS 泄露** — 使用国内 DNS 会暴露真实地理位置
- **IP 风险过高** — 机房 IP 或被滥用的 IP 更容易触发风控
- **时区不一致** — 本地时区配置与 IP 所在地不匹配，增加异常检测概率

`ip_check` 一键检测这些问题，帮你在使用 AI 工具前排除隐患。

### 功能

| 检测项 | 说明 |
|--------|------|
| 局域网 IP / IPv6 | 检测本机 IP，确认 IPv6 是否已禁用 |
| DNS 服务器 | 识别 DNS 来源（国内/国外），标注已知 DNS 服务商 |
| 公网 IP 信息 | 出口 IP、国家、地区、ISP、运营商 |
| 代理检测 | 环境变量代理配置、IP 是否被标记为代理 |
| IP 类型 | 住宅 IP / 机房 IP 识别 |
| IP 风险评分 | 通过 proxycheck.io 查询风险分数 |
| 滥用记录 | 通过 StopForumSpam 查询 IP 是否被举报 |
| 时区一致性 | 对比本地 CLI 时区与公网 IP 所在时区是否匹配 |

### 快速开始

```bash
python ip_check.py
```

首次运行会自动检测并提示安装缺少的依赖（`requests` 等）。

#### 环境要求

- Python 3.7+
- 支持 macOS / Linux / Windows

### 结果说明

**局域网 & DNS** — IPv6 建议禁用，大部分代理不处理 IPv6 流量，开启后可能同时暴露两个不同地区的 IP 地址。如果检测到国内 DNS，需要在代理软件中调整 DNS 设置。

**公网 IP 信息** — 显示经过代理后的出口 IP、所在国家/地区、ISP 和时区。这些信息直接影响 AI 服务对你请求来源的判断。

**IP 风险评估** — 检测 IP 是住宅还是机房类型。机房 IP 不一定有问题，但会进一步查询风险评分和滥用记录。如果风险评分偏高，建议更换节点。

**时区一致性** — 对比本地 `$TZ` 环境变量（或系统时区）与公网 IP 所在时区。不一致会增加被 AI 服务识别为异常的概率。建议在 shell 配置中设置 `TZ` 为与 IP 所在地匹配的 IANA 时区（如 `America/Los_Angeles`）。

---

## License

This project is licensed under the [MIT License](LICENSE).
