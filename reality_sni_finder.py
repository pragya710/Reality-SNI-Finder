#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reality SNI Finder
- Scans ref /24 plus ±N neighbor /24 blocks with masscan (tcp/443).
- TLS probe without SNI; extracts CN/SAN. If SANs are empty, uses OpenSSL x509 -text fallback.
- Expands wildcard SANs: "*.example.com" → "example.com", "www.example.com".
- Verifies real HTTP/2 with curl --resolve.
- Scores by latency and numeric IP distance (no external deps).
- Output: top 30 unique domains → domains.txt.
- Shows progress bars; quiet otherwise.

Env overrides (optional):
  RSF_BLOCKS (default 10), RSF_RATE (6000), RSF_TIMEOUT (8), RSF_THREADS (128),
  RSF_INCLUDE_GENERIC (1/0), RSF_VERIFY_H2 (1/0), RSF_REF_IP (IPv4).
"""

import ipaddress, math, os, re, shlex, socket, ssl, subprocess, sys, time, threading
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Set

# ---------------- Progress bar ----------------
class Progress:
    def __init__(self, total: int, title: str, width: int = 46):
        self.total = max(1, total); self.title = title; self.width = width
        self.done = 0; self.lock = threading.Lock(); self.start = time.time()
        self._render()
    def advance(self, n: int = 1):
        with self.lock:
            self.done = min(self.total, self.done + n); self._render()
    def finish(self):
        with self.lock:
            self.done = self.total; self._render(end=True)
    def _render(self, end: bool=False):
        ratio = self.done / self.total
        filled = int(self.width * ratio)
        bar = "█" * filled + "░" * (self.width - filled)
        pct = f"{int(ratio*100):3d}%"; elapsed = time.time() - self.start
        msg = f"\r{self.title} [{bar}] {pct}  ({self.done}/{self.total}, {elapsed:0.1f}s)"
        sys.stdout.write(msg); sys.stdout.flush()
        if end: sys.stdout.write("\n")

# ---------------- Helpers ----------------
def die(msg: str, code: int = 1):
    sys.stderr.write(f"[!] {msg}\n"); sys.exit(code)

def check_tool(tool: str):
    from shutil import which
    if which(tool) is None: die(f"Required tool not found: {tool}")

def public_ipv4_autodetect(timeout: float = 4.0) -> Optional[str]:
    # curl first, ifconfig.me fallback, then OpenDNS
    cmds = [
        "curl -fsS --max-time 4 https://api.ipify.org",
        "curl -fsS --max-time 4 https://ifconfig.me",
        "dig +short myip.opendns.com @resolver1.opendns.com"
    ]
    for c in cmds:
        try:
            ip = subprocess.check_output(["bash","-lc",c], text=True).strip()
            if ip:
                ipaddress.ip_address(ip)
                if ":" not in ip:
                    return ip
        except Exception:
            pass
    return None

def base24(ip: str) -> ipaddress.IPv4Network:
    a = ipaddress.ip_address(ip)
    if a.version != 4: die("Only IPv4 is supported.")
    return ipaddress.ip_network(f"{ip}/24", strict=False)

def neighbor_24_cidrs(ref_ip: str, blocks_each_side: int) -> List[str]:
    ref_net = base24(ref_ip); ref_base = int(ipaddress.ip_address(str(ref_net.network_address)))
    out=[]
    for off in range(-blocks_each_side, blocks_each_side+1):
        b = ref_base + off*256
        if 0 <= b <= 0xFFFFFFFF:
            out.append(str(ipaddress.ip_network(f"{ipaddress.ip_address(b)}/24", strict=True)))
    seen=set(); ordered=[]
    for c in out:
        if c not in seen: seen.add(c); ordered.append(c)
    return ordered

def parse_masscan(text: str) -> List[str]:
    ips=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[0]=="open" and parts[1]=="tcp":
            ips.append(parts[3])
    return sorted(set(ips))

def run_masscan_cidr(cidr: str, rate: int) -> List[str]:
    cmd = f"masscan {shlex.quote(cidr)} -p443 --rate {rate} --wait 0 --open-only -oL -"
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return parse_masscan(p.stdout)

def probe_tls_no_sni(ip: str, timeout: float = 3.0) -> Dict:
    res={"ip":ip,"ok":False,"latency_ms":None,"alpn":None,"has_tls13":False,"cert_cn":None,"cert_sans":[]}
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception: pass
    try: ctx.set_alpn_protocols(["h2","http/1.1"])
    except Exception: pass
    t0=time.time()
    try:
        with socket.create_connection((ip,443),timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                res["latency_ms"]=round((time.time()-t0)*1000,2); res["ok"]=True
                try: res["alpn"]=ssock.selected_alpn_protocol()
                except Exception: res["alpn"]=None
                res["has_tls13"]=(ssock.version()=="TLSv1.3")
                cert = ssock.getpeercert()
                if cert:
                    for tup in cert.get("subject",[]):
                        for k,v in tup:
                            if getattr(k, "lower", lambda: k)().lower()=="commonname":
                                res["cert_cn"]=v
                    res["cert_sans"]=[v for (t,v) in cert.get("subjectAltName",[]) if getattr(t,"lower",lambda:t)().lower()=="dns"]
    except Exception:
        pass
    # Strong OpenSSL fallback for SANs
    if res["ok"] and not res["cert_sans"]:
        try:
            cmd = f"echo | openssl s_client -connect {ip}:443 -showcerts 2>/dev/null | openssl x509 -noout -text"
            out = subprocess.getoutput(cmd)
            if out.strip():
                res["cert_sans"] = re.findall(r"DNS:([^,\s]+)", out)
        except Exception:
            pass
    return res

GENERIC_SAN = set([
    "sni.cloudflaressl.com","ssl.cloudflare.com","akamai.net",
    "cloudfront.net","edgekey.net","edgesuite.net"
])

def is_domain(d: str)->bool:
    d=d.strip().lower()
    return "." in d and not d.endswith(".local") and not d.endswith(".lan") and len(d)<253

def expand_wildcard(d: str)->List[str]:
    if d.startswith("*.") and d.count(".")>=2:
        root=d[2:]; return [root, f"www.{root}"]
    return [d]

def domains_from_cert(cn, sans, include_generic=True)->List[str]:
    items=[]
    if cn and is_domain(cn): items.extend(expand_wildcard(cn.lower()))
    for s in sans or []:
        s=s.strip().lower()
        if not is_domain(s): continue
        if (not include_generic) and (s in GENERIC_SAN): continue
        items.extend(expand_wildcard(s))
    seen=set(); out=[]
    for i in items:
        if i not in seen: seen.add(i); out.append(i)
    return out

def verify_http2(domain: str, ip: str, timeout: float=8.0)->bool:
    cmd=["curl","-sS","-m",str(int(timeout)),"--http2","-o","/dev/null","--resolve",f"{domain}:443:{ip}",f"https://{domain}/"]
    try:
        p=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return p.returncode==0
    except Exception:
        return False

def ipnum_dist_norm(a: str, b: str)->float:
    try:
        d = abs(int(ipaddress.ip_address(a))-int(ipaddress.ip_address(b)))
        return d/(2**32)*1000.0
    except Exception:
        return 1000.0

# ---------------- Main ----------------
def main():
    blocks = int(os.environ.get("RSF_BLOCKS", "10"))
    rate = int(os.environ.get("RSF_RATE", "6000"))
    timeout = float(os.environ.get("RSF_TIMEOUT", "8"))
    threads = int(os.environ.get("RSF_THREADS", "128"))
    include_generic = os.environ.get("RSF_INCLUDE_GENERIC", "1") == "1"
    verify_h2 = os.environ.get("RSF_VERIFY_H2", "1") == "1"
    ref_ip_env = os.environ.get("RSF_REF_IP", "").strip()
    TOPN = 30  # fixed as requested

    for tool in ("masscan","curl","openssl"):
        check_tool(tool)

    ref_ip = ref_ip_env or public_ipv4_autodetect()
    if not ref_ip:
        die("Cannot detect public IPv4 automatically. Set RSF_REF_IP or ensure outbound DNS/HTTP works.")

    # Build block list
    cidrs = neighbor_24_cidrs(ref_ip, blocks)

    # Scan
    ips_all=[]
    pb = Progress(len(cidrs), "Scanning blocks")
    for cidr in cidrs:
        ips_all.extend(run_masscan_cidr(cidr, rate)); pb.advance(); time.sleep(0.03)
    pb.finish()
    ips = sorted(set(ips_all))
    if not ips: die("No hosts with port 443 were found.")

    # Probe
    pb2 = Progress(len(ips), "TLS probing")
    probes=[]
    def _probe(ip):
        r=probe_tls_no_sni(ip, timeout=max(3.0, timeout-2)); pb2.advance(); return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_probe, ips):
            if r.get("ok"): probes.append(r)
    pb2.finish()
    if not probes: die("No TLS-capable hosts responded.")

    # Domains from certs
    candidates=[]
    for p in probes:
        for d in domains_from_cert(p["cert_cn"], p["cert_sans"], include_generic=include_generic):
            candidates.append((p["ip"], p["latency_ms"], d))
    if not candidates: die("No domains extracted from certificates.")

    # Verify HTTP/2
    if verify_h2:
        pb3 = Progress(len(candidates), "Verifying HTTP/2")
        filtered=[]
        def _verify(t):
            ip, lat, dom = t
            ok = verify_http2(dom, ip, timeout=timeout); pb3.advance()
            return (ip, lat, dom, ok)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for ip, lat, dom, ok in ex.map(_verify, candidates):
                if ok: filtered.append((ip, lat, dom))
        pb3.finish()
        candidates = filtered
        if not candidates: die("No domains passed real HTTP/2 verification.")

    # Score: latency + 0.3 * normalized numeric IP distance
    scored=[]
    for ip, lat, dom in candidates:
        score = (lat if (lat is not None) else 5000.0) + 0.3*ipnum_dist_norm(ip, ref_ip)
        scored.append((score, dom))
    scored.sort(key=lambda x: x[0])

    # Write top 30 unique domains
    seen=set(); top=[]
    for _, dom in scored:
        if dom not in seen:
            seen.add(dom); top.append(dom)
        if len(top)>=TOPN: break
    with open("domains.txt","w",encoding="utf-8") as f:
        f.write("\n".join(top))
    print(f"\n[✓] Wrote {len(top)} domains to domains.txt")

if __name__=="__main__":
    main()
