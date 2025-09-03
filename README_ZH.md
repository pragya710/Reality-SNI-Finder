🌐 Available in: [English](README.md) | [فارسی](README_FA.md) | [Русский](README_RU.md) | [中文](README_ZH.md)

# Reality SNI Finder

**Reality SNI Finder** 会发现托管在 **接近您VPS的IP** 上的 HTTPS 域名（SNI 候选），这样您就可以为 **Xray/Reality** 选择低延迟、路径优化的 SNI 值。  
该工具会扫描您服务器的 /24 段以及前后 ±N 个相邻 /24 段，在 **无SNI** 的情况下探测 TLS，提取证书 CN/SAN（带有强大的 OpenSSL 备用方案），使用 `curl --resolve` 验证 **真实 HTTP/2**，根据接近程度对候选进行排名，并将 **前30个域名** 写入 `domains.txt`。

> ⚠️ **请负责任地使用。** 扫描 IP 范围——即使速率很低——也可能违反 Acceptable Use Policy (AUP) 或当地法律。请阅读下面的 **法律声明**，并且仅在您拥有授权的情况下操作。

---

## 一键安装和运行

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ShatakVPN/Reality-SNI-Finder/main/reality_sni_finder.sh)"
```

启动菜单：

- **Start scan** — 使用当前设置运行  
- **Settings** — 调整扫描范围、速率、超时、线程、HTTP/2 验证、包含/排除通用 SAN，以及参考 IP  
- **Install/Check dependencies** — masscan, curl, openssl, python3  
- **View output** — 快速预览结果域名  
- **Clean output** — 删除 `domains.txt`  

设置会保存到 `.rsf.conf`。

---

## 为什么接近的 SNI 对 V2Ray/Reality 很重要？

Reality 依赖于 TLS 内的 **SNI (Server Name Indication)** 来伪装和路由流量。选择 **在拓扑上接近您VPS的域名** 带来实际好处：

- **更低延迟**：TLS 握手和数据传输更快完成。  
- **更少跳数，更少故障**：路径更短意味着更少抖动和丢包。  
- **更高吞吐量**：更低的 RTT 改善 TCP 拥塞控制，HTTP/2 多路复用获益更多。  
- **更稳定的路由**：接近的节点在拥塞或故障时更不容易绕远路。  
- **更好的隐蔽性**：使用靠近VPS的真实可达域名减少路径异常。  

总结：一个 **接近且支持HTTP/2的SNI** 能提供 **更流畅、更快速、更稳定** 的体验。

---

## 工具功能

1. 使用 `masscan` 在 TCP/443 上 **发现 IP**（您 VPS 的 /24 和相邻 ±N /24 段）。  
2. **无 SNI 探测 TLS** 并提取证书 CN/SAN。如果 SAN 列表为空，使用 OpenSSL：  
   ```
   openssl s_client -showcerts | openssl x509 -noout -text
   ```  
3. **展开通配符域名** (`*.example.com` → `example.com`, `www.example.com`)  
4. 使用 `curl --resolve` **验证真实 HTTP/2**  
5. 根据延迟和数值 IP 距离 **打分**  
6. 将 **前30个域名** 写入 `domains.txt`  

---

## 要求

- Linux（建议 root 权限运行 masscan）  
- masscan, curl, openssl, python3  
- 出站 HTTP/DNS 访问  

---

## 使用方法

### 启动程序

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/reality_sni_finder.sh)"
```

扫描完成后：

```
./domains.txt   # 前30个域名
```

### 设置选项

- **Blocks each side**: 相邻 /24 段数量（默认: 10）  
- **Masscan rate (pps)**: 默认 6000  
- **Timeout (sec)**: 默认 8  
- **Threads**: 默认 128  
- **Verify HTTP/2**: 开启（默认）或关闭  
- **Include generic SANs**: 开启/关闭  
- **Override ref IP**: 手动指定参考 IP  

### 环境变量（高级用法）

示例：

```bash
export RSF_BLOCKS=8 RSF_RATE=4000 RSF_VERIFY_H2=1
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/reality_sni_finder.sh)"
```

---

## 输出结果

- **`domains.txt`** — 精确 30 个唯一域名，按优先级排序  

提示：在生产环境使用前，务必验证域名仍支持 HTTP/2 并可访问。

---

## 性能与安全提示

- 保守起步：`RSF_BLOCKS=6` 和 `RSF_RATE=4000`  
- 使用 root 权限运行以提升 masscan 效率  
- 避免一次性扫描过大范围  

---

## 法律声明

该工具执行 **网络扫描** 和 TLS 探测。即使在中等速率下：  
- 可能违反提供商的 AUP 或 ToS  
- 可能触发警告或限制  
- 在您的司法辖区可能是非法的  

您对使用方式承担全部责任。  
**仅扫描您有权限的范围。**

---

## 排名方式

评分 = `latency_ms + 0.3 * normalized_numeric_ip_distance`  
越低越好。  

---

## 故障排查

- **未找到域名** → 缩小范围，增加超时  
- **Permission denied** → 以 root 运行  
- **未检测到公共 IP** → 手动设置 `RSF_REF_IP`  
- **频繁 HTTP/2 失败** → 部分域名需要 SNI  

---

## 卸载

```bash
rm -f reality_sni_finder.sh reality_sni_finder.py .rsf.conf domains.txt
```

---

## 仓库热度

[![Stargazers over time](https://starchart.cc/ShatakVPN/Reality-SNI-Finder.svg?variant=adaptive)](https://starchart.cc/ShatakVPN/Reality-SNI-Finder)

**享受更快、更稳定的 Reality。请谨慎扫描。**
