# Reality SNI Finder

**Reality SNI Finder** discovers HTTPS domains (SNI candidates) hosted on IPs **near your VPS** so you can pick SNI values that are low-latency and path-efficient for **Xray/Reality**.  
It scans the /24 block of your server and ±N neighboring /24 blocks, probes TLS **without SNI**, extracts CN/SAN (with a strong OpenSSL fallback), verifies **real HTTP/2** with `curl --resolve`, ranks candidates by proximity, and writes the **top 30** domains to `domains.txt`.

> ⚠️ **Use responsibly.** Scanning IP ranges—even at modest rates—may violate Acceptable Use Policies (AUP) or local laws. Read the **Legal Notice** below and operate only where you have authorization.

---

## One-line install & run

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ShatakVPN/Reality-SNI-Finder/main/reality_sni_finder.sh)"
```

The launcher shows a clean menu:

- **Start scan** — run with current settings.
- **Settings** — adjust scan blocks, rate, timeout, threads, HTTP/2 verification, include/exclude generic SANs, and reference IP override.
- **Install/Check dependencies** — masscan, curl, openssl, python3.
- **View output** — quick preview of the resulting domains.
- **Clean output** — remove `domains.txt`.

Settings are saved to a local `.rsf.conf`.

---

## Why nearby SNI matters for V2Ray/Reality

Reality relies on **Domain Fronting–style SNI** (the Server Name Indication inside TLS) to camouflage and route traffic. Choosing SNI values **topologically close to your VPS** yields tangible benefits:

- **Lower latency**: TLS handshakes and data flows complete faster when the SNI’s serving edge sits near your VPS.  
- **Fewer network hops, fewer timeouts**: Shorter paths mean less jitter, fewer packet drops, and fewer mid-path failures.  
- **Higher throughput**: Tighter RTTs improve TCP congestion control; HTTP/2 multiplexing benefits from reduced head-of-line blocking.  
- **More stable routes**: Nearby edges are less likely to reroute via distant regions during congestion or partial outages.  
- **Better stealth characteristics**: Using valid, reachable domains that already terminate close to your VPS reduces anomalies in path selection.

In short: a **nearby, HTTP/2-capable SNI** tends to produce a **smoother, faster, and more resilient** user experience.

---

## What it does

1. **Discovers IPs** with `masscan` on TCP/443 across your VPS’s /24 and ±N neighbor /24s.
2. **Probes TLS without SNI** and extracts certificate **CN/SAN**. If Python’s SSL reports an empty SAN list, it falls back to:
   ```
   openssl s_client -showcerts | openssl x509 -noout -text
   ```
   and parses `DNS:` entries.
3. **Expands wildcards** (`*.example.com` → `example.com`, `www.example.com`).
4. **Verifies real HTTP/2** using `curl --resolve` (configurable).
5. **Scores** by measured latency plus normalized numeric IP distance relative to your VPS IP.
6. **Writes the top 30** unique domains to `domains.txt` (best-first).

---

## Requirements

- Linux (root recommended for fast `masscan`)
- `masscan`, `curl`, `openssl`, `python3`
- Outbound HTTP/DNS (for detecting your public IPv4 with `curl`/`dig`)

The launcher can install dependencies for most distributions (Debian/Ubuntu, RHEL/CentOS/Alma, Arch, openSUSE, Alpine).

---

## Usage

### Run the launcher

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/reality_sni_finder.sh)"
```

Choose **Start scan**. When it finishes, check:

```
./domains.txt   # top 30 ranked SNI candidates
```

### Settings (from the launcher)

- **Blocks each side**: how many neighbor /24s around your VPS’s /24 (default: **10**, so total **21** /24 blocks)
- **Masscan rate (pps)**: conservative default **6000**; raise carefully
- **Timeout (sec)**: default **8**
- **Threads**: default **128**
- **Verify HTTP/2**: on/off (default **on**)
- **Include generic SANs**: on/off (default **on**). Turning off may exclude CDN generic names.
- **Override ref IP**: by default the engine detects your public IPv4; set this to force a specific reference IP

Settings persist in `.rsf.conf`.

### Environment overrides (advanced)

You can also export these before starting the launcher:

| Variable             | Default | Description                              |
|----------------------|---------|------------------------------------------|
| `RSF_BLOCKS`         | `10`    | Neighbor /24s each side                  |
| `RSF_RATE`           | `6000`  | masscan packets per second               |
| `RSF_TIMEOUT`        | `8`     | verification timeout (sec)               |
| `RSF_THREADS`        | `128`   | concurrency                              |
| `RSF_VERIFY_H2`      | `1`     | `1`=verify HTTP/2, `0`=skip              |
| `RSF_INCLUDE_GENERIC`| `1`     | `1`=include generic SANs, `0`=exclude    |
| `RSF_REF_IP`         | (auto)  | override detected public IPv4            |
| `RSF_PY_URL`         | (auto)  | URL of `reality_sni_finder.py` to fetch  |

Example:

```bash
export RSF_BLOCKS=8 RSF_RATE=4000 RSF_VERIFY_H2=1
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/reality_sni_finder.sh)"
```

---

## Output

- **`domains.txt`** — exactly **30** unique domains, best-first. These are strong SNI candidates to use in your V2Ray/Reality configs.

> Tip: Always validate that your chosen domain still serves HTTP/2 and remains reachable from your deployment region before putting it into production.

---

## Performance & safety tips

- Start conservatively: **`RSF_BLOCKS=6`** and **`RSF_RATE=4000`**. Scale up only if needed.  
- Running as **root** allows `masscan` to use raw sockets efficiently. If you cannot run as root, reduce PPS.  
- Avoid scanning enormous ranges in one go; patience beats alarms.

---

## Legal notice (read this)

This tool performs **network scanning** and TLS probing. Even at moderate rates, scanning can:
- Violate a provider’s **Acceptable Use Policy (AUP)** or **Terms of Service**.
- Trigger automated abuse **alerts** or **throttling**.
- Be illegal in your jurisdiction **without authorization**.

You are solely responsible for how you use this software.  
**Only scan ranges you are authorized to test.** Keep your rate and scope modest. Respect local laws and any contractual restrictions from your hosting provider, ISP, and cloud/CDN vendors.

---

## How it ranks results (at a glance)

Score = `latency_ms + 0.3 * normalized_numeric_ip_distance`

- Lower is better.  
- This favors sockets that responded quickly during TLS probing and that are numerically close to your VPS’s IP block.  
- You can further refine by disabling generic SANs or adjusting the neighborhood size and PPS.

---

## Troubleshooting

- **No domains found**  
  Reduce scope and rate; increase `RSF_TIMEOUT` to `10`; try `RSF_INCLUDE_GENERIC=1`.  
  Verify `curl --http2` works from your server.  
- **Permission denied / raw socket issues**  
  Run the launcher as root (the script auto-elevates with `sudo` when present).  
- **Public IP not detected**  
  Set `RSF_REF_IP` explicitly (e.g., `export RSF_REF_IP=203.0.113.10`).  
- **HTTP/2 verify fails often**  
  Some domains require SNI to advertise `h2`; others don’t. Keep verification enabled for higher quality; temporarily disable if you need a broader candidate set, then re-test your final picks.

---

## Uninstall

Remove all files:

```bash
rm -f reality_sni_finder.sh reality_sni_finder.py .rsf.conf domains.txt
```

---

## Repository Popularity
[![Stargazers over time](https://starchart.cc/ShatakVPN/Reality-SNI-Finder.svg?variant=adaptive)](https://starchart.cc/ShatakVPN/Reality-SNI-Finder)

**Enjoy faster, steadier Reality configs with SNI targets that actually live near your server. Stay on the right side of the line—scan kindly.**
