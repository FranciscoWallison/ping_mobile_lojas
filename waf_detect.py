"""
waf_detect.py  —  "o que está na frente deste site/API, e quem está me bloqueando?"
-----------------------------------------------------------------------------------
Análise LOCAL (a partir da sua rede) da pilha de rede de um alvo:

  1. Seu IP de saída e ASN          -> é esse IP que o WAF enxerga
  2. DNS local x DNS público        -> CNAME de CDN e split-horizon (DNS interno)
  3. ASN dos IPs do alvo            -> CDN em nuvem ou datacenter próprio (appliance)
  4. Requisição com vários clientes -> headers, cookies e página de bloqueio
  5. Pilha detectada + quem bloqueou + ID para o time de infra

Uso:
    python waf_detect.py odontoprev.com.br
    python waf_detect.py https://api.exemplo.com/v1/rota -X POST \\
        -H "Content-Type: application/json" -d '{"id": 1}'
    python waf_detect.py exemplo.com --perfis curl navegador insomnia okhttp
    python waf_detect.py exemplo.com --json exemplo_waf.json

Rode o mesmo comando em duas redes (ex.: sua máquina e a máquina do domínio)
e compare: se a pilha for igual e só o resultado mudar, a regra é por IP/rede.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import requests

from waf_fingerprint import (
    BlockInfo, Detection, classify_block, describe_asn, fingerprint_asn,
    fingerprint_cname, fingerprint_response, merge_detections, normalize_headers,
)

OUTPUT_DIR = Path(__file__).parent / "output"
DOH = "https://dns.google/resolve"
TIMEOUT = 20

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

# Perfis de cliente: só trocam User-Agent/Accept. A impressão digital TLS
# (JA3/JA4) continua sendo a do Python em todos eles.
PROFILES: dict[str, dict[str, str]] = {
    "curl": {"User-Agent": "curl/8.9.1", "Accept": "*/*"},
    "navegador": {
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
    },
    "insomnia": {"User-Agent": "insomnia/10.1.1", "Accept": "*/*"},
    "postman": {"User-Agent": "PostmanRuntime/7.42.0", "Accept": "*/*"},
    "okhttp": {"User-Agent": "okhttp/4.12.0", "Accept": "*/*"},           # app Android
    "ios": {"User-Agent": "App/1 CFNetwork/1498.700.2 Darwin/23.6.0", "Accept": "*/*"},
    "python": {"User-Agent": f"python-requests/{requests.__version__}", "Accept": "*/*"},
}
DEFAULT_PROFILES = ["curl", "navegador"]


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------
@dataclass
class ProbeResult:
    profile: str
    user_agent: str
    status: int | None = None
    elapsed_ms: float | None = None
    error: str = ""
    redirects: list[str] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)
    detections: list[dict] = field(default_factory=list)
    block: dict | None = None


@dataclass
class WafReport:
    url: str
    host: str
    egress_ip: str = ""
    egress_asn: str = ""
    dns_local: list[str] = field(default_factory=list)
    dns_public: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    split_horizon: bool = False
    target_asns: dict[str, str] = field(default_factory=dict)
    cloudflare_trace: dict[str, str] = field(default_factory=dict)
    probes: list[ProbeResult] = field(default_factory=list)
    stack: list[dict] = field(default_factory=list)
    diagnosis: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DNS / ASN (DNS-over-HTTPS + Team Cymru — só precisa de `requests`)
# ---------------------------------------------------------------------------
def doh(name: str, rtype: str) -> list[dict]:
    try:
        r = requests.get(DOH, params={"name": name, "type": rtype}, timeout=10)
        return r.json().get("Answer") or []
    except Exception:
        return []


def asn_lookup(ip: str) -> tuple[int | None, str]:
    """Retorna (ASN, nome) via Team Cymru. Funciona para IPv4 e IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, ""
    if addr.is_private:
        return None, "IP privado (rede interna)"
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        q = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    ans = [a["data"].strip('"') for a in doh(q, "TXT")]
    if not ans:
        return None, ""
    asn = int(ans[0].split("|")[0].strip().split()[0])
    name_ans = [a["data"].strip('"') for a in doh(f"AS{asn}.asn.cymru.com", "TXT")]
    name = name_ans[0].split("|")[-1].strip() if name_ans else ""
    return asn, re.sub(r"^AS\d+\s*-\s*", "", name)


def resolve_local(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def egress_info() -> tuple[str, int | None, str]:
    try:
        ip = requests.get("https://api.ipify.org", timeout=10).text.strip()
    except Exception:
        return "", None, ""
    asn, name = asn_lookup(ip)
    return ip, asn, name


def cloudflare_trace(host: str) -> dict[str, str]:
    """/cdn-cgi/trace mostra o IP e o PoP que o Cloudflare enxerga para você."""
    try:
        r = requests.get(f"https://{host}/cdn-cgi/trace", timeout=10,
                         headers={"User-Agent": PROFILES["curl"]["User-Agent"]})
        if r.status_code != 200 or "colo=" not in r.text:
            return {}
        return dict(line.split("=", 1) for line in r.text.splitlines() if "=" in line)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _raw_headers(resp: requests.Response) -> dict[str, list[str]]:
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return normalize_headers([(k, v) for k in raw.keys() for v in raw.getlist(k)])
    return normalize_headers(resp.headers)


def probe(url: str, profile: str, method: str, headers: dict[str, str],
          data: str | None) -> tuple[ProbeResult, list[Detection]]:
    hdrs = {**PROFILES[profile], **headers}
    res = ProbeResult(profile=profile, user_agent=hdrs.get("User-Agent", ""))
    try:
        resp = requests.request(method, url, headers=hdrs, data=data.encode() if data else None,
                                timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        res.error = str(e).splitlines()[0][:200]
        return res, []

    res.status = resp.status_code
    res.elapsed_ms = round(resp.elapsed.total_seconds() * 1000, 1)
    res.redirects = [f"{h.status_code} {h.headers.get('location', '')}" for h in resp.history]
    res.headers = _raw_headers(resp)

    # Fingerprint de toda a cadeia (redirects incluídos): cookies do F5/CDN
    # costumam aparecer só no primeiro hop.
    dets: list[Detection] = []
    for hop in [*resp.history, resp]:
        dets = merge_detections(dets, fingerprint_response(_raw_headers(hop), hop.text[:50000]))
    res.detections = [asdict(d) for d in dets]

    block = classify_block(resp.status_code, res.headers, resp.text[:50000])
    res.block = asdict(block) if block else None
    return res, dets


# ---------------------------------------------------------------------------
# Análise
# ---------------------------------------------------------------------------
def analyze(url: str, method: str, headers: dict[str, str], data: str | None,
            profiles: list[str]) -> WafReport:
    if "://" not in url:
        url = "https://" + url
    host = urlsplit(url).hostname or url
    rep = WafReport(url=url, host=host)

    print("[+] IP de saída desta máquina...")
    ip, asn, name = egress_info()
    rep.egress_ip = ip
    rep.egress_asn = f"AS{asn} {name}".strip() if asn else ""

    print(f"[+] DNS de {host} (local x público)...")
    rep.dns_local = resolve_local(host)
    answers = doh(host, "A") + doh(host, "AAAA")
    rep.cname_chain = sorted({a["data"].rstrip(".") for a in answers if a.get("type") == 5})
    rep.dns_public = sorted({a["data"] for a in answers if a.get("type") in (1, 28)})

    print("[+] ASN dos IPs do alvo...")
    asn_dets: list[Detection] = []
    asns_local, asns_public = set(), set()
    for ip_ in sorted(set(rep.dns_local) | set(rep.dns_public))[:6]:
        a, n = asn_lookup(ip_)
        rep.target_asns[ip_] = describe_asn(a, n) if a else (n or "ASN desconhecido")
        asn_dets = merge_detections(asn_dets, fingerprint_asn(a, n))
        if ip_ in rep.dns_local:
            asns_local.add(a or n)
        if ip_ in rep.dns_public:
            asns_public.add(a or n)
    # Split-horizon: a rede local resolve o nome para outra rede (ex.: IP interno
    # que não passa pelo WAF de borda). Compara por ASN porque CDNs devolvem
    # IPs diferentes por região sem que isso seja um problema.
    rep.split_horizon = bool(rep.dns_local and rep.dns_public and asns_local != asns_public)

    stack = merge_detections(fingerprint_cname(rep.cname_chain), asn_dets)
    for profile in profiles:
        print(f"[+] {method} {url} como '{profile}'...")
        res, dets = probe(url, profile, method, headers, data)
        rep.probes.append(res)
        stack = merge_detections(stack, dets)

    if any(d.vendor == "Cloudflare" for d in stack):
        rep.cloudflare_trace = cloudflare_trace(host)

    rep.stack = [asdict(d) for d in stack]
    rep.diagnosis = build_diagnosis(rep, stack)
    return rep


def build_diagnosis(rep: WafReport, stack: list[Detection]) -> list[str]:
    out: list[str] = []
    ok = [p for p in rep.probes if p.status is not None and p.status < 400]
    bad = [p for p in rep.probes if p.status is not None and p.status >= 400]
    err = [p for p in rep.probes if p.status is None]

    if not stack:
        out.append("Nenhuma assinatura conhecida: headers podem ter sido removidos de propósito. "
                   "Use o ASN do IP e a página de erro para inferir.")

    if rep.split_horizon:
        out.append("DNS local difere do público (split-horizon): nesta rede o nome aponta para "
                   "outro destino. Máquinas da rede interna podem acessar a origem sem passar "
                   "pelo WAF de borda — isso explica 200 lá e 403 fora.")

    if bad and ok:
        names_bad = ", ".join(p.profile for p in bad)
        names_ok = ", ".join(p.profile for p in ok)
        out.append(f"O bloqueio depende do cliente: [{names_bad}] bloqueado(s), [{names_ok}] "
                   "liberado(s). A regra olha User-Agent/assinatura de bot, não o seu IP.")
    elif bad and not ok:
        out.append("Todos os perfis foram bloqueados: a regra não depende do User-Agent. "
                   "Suspeite de IP/ASN/país de saída, reputação do IP ou regra por caminho/método. "
                   "Rode este script em outra rede (ex.: máquina do domínio) e compare.")
    elif ok and not bad:
        out.append("Nenhum perfil foi bloqueado a partir desta rede.")
    if err:
        out.append("Sem resposta HTTP em: " + ", ".join(f"{p.profile} ({p.error})" for p in err)
                   + ". Timeout costuma ser descarte silencioso (firewall/IP Intelligence).")

    seen = set()
    for p in bad:
        if p.block and p.block["kind"] not in seen:
            seen.add(p.block["kind"])
            b = BlockInfo(**p.block)
            out.append(f"Quem bloqueou: {b.short()}. {b.hint}")

    trace = rep.cloudflare_trace
    if trace.get("ip"):
        out.append(f"O Cloudflare enxerga esta máquina como {trace['ip']} "
                   f"(PoP {trace.get('colo', '?')}, país {trace.get('loc', '?')}, "
                   f"WARP {trace.get('warp', '?')}). Se a VPN estivesse no caminho, este "
                   "seria o IP da VPN.")
    if rep.egress_ip and trace.get("ip") and trace["ip"] != rep.egress_ip:
        out.append("O IP visto pelo Cloudflare difere do IP de saída geral: há rota/proxy "
                   "específico para este destino.")
    return out


# ---------------------------------------------------------------------------
# Saída
# ---------------------------------------------------------------------------
def print_report(rep: WafReport) -> None:
    line = "=" * 78
    print("\n" + line)
    print(f" PILHA DE REDE — {rep.url}")
    print(line)
    print(f" Sua saída      : {rep.egress_ip or '?'}  {rep.egress_asn}")
    print(f" DNS local      : {', '.join(rep.dns_local) or '-'}")
    print(f" DNS público    : {', '.join(rep.dns_public) or '-'}")
    if rep.cname_chain:
        print(f" CNAME          : {' -> '.join(rep.cname_chain)}")
    for ip, desc in rep.target_asns.items():
        print(f" ASN {ip:<11}: {desc}")

    print("\n Pilha detectada (internet -> aplicação):")
    if not rep.stack:
        print("   (nenhuma assinatura conhecida)")
    for d in rep.stack:
        det = Detection(**d)
        print(f"   - {det.label}")
        for ev in det.evidence[:4]:
            print(f"       . {ev}")

    print("\n Requisições:")
    for p in rep.probes:
        status = p.status if p.status is not None else "sem resposta"
        print(f"   [{p.profile:<9}] HTTP {status}"
              + (f"  {p.elapsed_ms:.0f}ms" if p.elapsed_ms is not None else "")
              + (f"  ({p.error})" if p.error else ""))
        if p.block:
            print(f"       -> {BlockInfo(**p.block).short()}")

    print("\n Diagnóstico:")
    for d in rep.diagnosis:
        print(f"   * {d}")
    print(line + "\n")


def save_json(rep: WafReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(rep), f, indent=2, ensure_ascii=False)
    print(f"[+] JSON salvo em {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    ap = argparse.ArgumentParser(
        description="Identifica CDN/WAF/balanceador/origem de um alvo e quem está bloqueando")
    ap.add_argument("url", help="URL ou domínio, ex: odontoprev.com.br ou https://host/rota")
    ap.add_argument("-X", "--method", default="GET")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help='header extra, ex: -H "Content-Type: application/json" (repetível)')
    ap.add_argument("-d", "--data", help="corpo da requisição (como no curl)")
    ap.add_argument("--perfis", nargs="+", default=DEFAULT_PROFILES, choices=sorted(PROFILES),
                    help=f"clientes a simular (padrão: {' '.join(DEFAULT_PROFILES)})")
    ap.add_argument("--json", dest="json_out", help="salvar resultado em JSON (em output/)")
    args = ap.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            ap.error(f"header inválido: {h!r} (use 'Nome: valor')")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    method = args.method.upper()
    if args.data and method == "GET":
        method = "POST"  # mesmo comportamento do curl -d

    rep = analyze(args.url, method, headers, args.data, args.perfis)
    print_report(rep)

    if args.json_out:
        OUTPUT_DIR.mkdir(exist_ok=True)
        json_path = args.json_out if os.sep in args.json_out or "/" in args.json_out \
            else str(OUTPUT_DIR / args.json_out)
        save_json(rep, json_path)


if __name__ == "__main__":
    main()
