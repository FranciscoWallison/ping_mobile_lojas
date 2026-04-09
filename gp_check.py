"""
gp_check.py  —  versão STANDALONE (arquivo único)
--------------------------------------------------
Valida disponibilidade multi-região de um alvo via GlobalPing API.

Uso:
    pip install requests
    python gp_check.py odontoprev.com.br
    python gp_check.py odontoprev.com.br --regions BR US DE JP
    python gp_check.py odontoprev.com.br --json saida.json

Sem dependências além de `requests`. Sem API key necessária.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict

import requests

API = "https://api.globalping.io/v1/measurements"
POLL_INTERVAL = 1.0
POLL_TIMEOUT = 60

DEFAULT_REGIONS = [
    "BR", "US", "DE", "GB", "JP", "SG", "AU", "ZA", "IN", "FR",
]


# ---------------------------------------------------------------------------
# Cliente GlobalPing
# ---------------------------------------------------------------------------
class GP:
    def __init__(self, token: str | None = None):
        self.s = requests.Session()
        self.s.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "gp-check-standalone/0.1",
        })
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def create(self, payload: dict) -> str:
        r = self.s.post(API, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()["id"]

    def fetch(self, mid: str) -> dict:
        r = self.s.get(f"{API}/{mid}", timeout=30)
        r.raise_for_status()
        return r.json()

    def run(self, payload: dict) -> dict:
        mid = self.create(payload)
        start = time.time()
        while True:
            data = self.fetch(mid)
            if data.get("status") == "finished":
                return data
            if time.time() - start > POLL_TIMEOUT:
                raise TimeoutError(f"measurement {mid} did not finish in {POLL_TIMEOUT}s")
            time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Relatório por região
# ---------------------------------------------------------------------------
@dataclass
class Report:
    region: str
    probe_country: str = ""
    probe_city: str = ""
    probe_asn: str = ""
    http_status: int | None = None
    http_total_ms: float | None = None
    http_dns_ms: float | None = None
    http_tcp_ms: float | None = None
    http_tls_ms: float | None = None
    http_first_byte_ms: float | None = None
    http_resolved_ip: str = ""
    http_tls_subject: str = ""
    http_tls_issuer: str = ""
    dns_resolved_ips: list[str] = field(default_factory=list)
    mtr_last_hop: str = ""
    mtr_packet_loss: float | None = None
    verdict: str = "UNKNOWN"
    notes: list[str] = field(default_factory=list)


def _meta(probe: dict) -> dict:
    p = probe.get("probe", {})
    return {
        "probe_country": p.get("country", ""),
        "probe_city": p.get("city", ""),
        "probe_asn": str(p.get("asn", "")),
    }


def _label(probe: dict, fallback: str) -> str:
    p = probe.get("probe", {})
    c, co = p.get("city", ""), p.get("country", "")
    return f"{c}, {co}" if c and co else (co or fallback)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def parse_http(res: dict, reports: dict[str, Report]):
    for probe in res.get("results", []):
        key = _label(probe, "http")
        rep = reports.setdefault(key, Report(region=key))
        rep.__dict__.update(_meta(probe))

        r = probe.get("result", {})
        raw = (r.get("rawOutput") or "").lower()
        t = r.get("timings") or {}
        rep.http_dns_ms = t.get("dns")
        rep.http_tcp_ms = t.get("tcp")
        rep.http_tls_ms = t.get("tls")
        rep.http_first_byte_ms = t.get("firstByte")
        rep.http_total_ms = t.get("total")
        rep.http_status = r.get("statusCode")
        rep.http_resolved_ip = r.get("resolvedAddress") or ""

        tls = r.get("tls") or {}
        if tls:
            rep.http_tls_subject = (tls.get("subject") or {}).get("CN", "")
            rep.http_tls_issuer = (tls.get("issuer") or {}).get("CN", "")

        if r.get("status") == "failed" or rep.http_status is None:
            if "timeout" in raw or "timed out" in raw:
                rep.verdict = "TIMEOUT"
                rep.notes.append("HTTP timeout no probe")
            elif "tls" in raw or "ssl" in raw or "certificate" in raw:
                rep.verdict = "TLS_FAIL"
                rep.notes.append((r.get("rawOutput") or "").splitlines()[0][:200])
            elif "getaddrinfo" in raw or "enotfound" in raw or "name resolution" in raw:
                rep.verdict = "DNS_FAIL"
                rep.notes.append("DNS não resolveu no probe")
            else:
                rep.verdict = "ERROR"
                line = (r.get("rawOutput") or "").strip().splitlines()
                rep.notes.append(line[0][:200] if line else "erro desconhecido")
        elif 200 <= rep.http_status < 400:
            rep.verdict = "OK"
        elif rep.http_status in (403, 451):
            rep.verdict = "BLOCKED"
            rep.notes.append(f"HTTP {rep.http_status} — provável bloqueio/WAF")
        elif rep.http_status >= 500:
            rep.verdict = "ERROR"
            rep.notes.append(f"HTTP {rep.http_status}")
        else:
            rep.notes.append(f"HTTP {rep.http_status}")


def parse_dns(res: dict, reports: dict[str, Report]):
    for probe in res.get("results", []):
        key = _label(probe, "dns")
        rep = reports.setdefault(key, Report(region=key))
        rep.__dict__.update(_meta(probe))
        r = probe.get("result", {})
        answers = r.get("answers") or []
        rep.dns_resolved_ips = [
            a.get("value") for a in answers
            if a.get("type") in ("A", "AAAA") and a.get("value")
        ]


def parse_mtr(res: dict, reports: dict[str, Report]):
    for probe in res.get("results", []):
        key = _label(probe, "mtr")
        rep = reports.setdefault(key, Report(region=key))
        rep.__dict__.update(_meta(probe))
        r = probe.get("result", {})
        hops = r.get("hops") or []
        if not hops:
            continue
        last = hops[-1]
        rep.mtr_last_hop = last.get("resolvedAddress") or last.get("resolvedHostname") or ""
        stats = last.get("stats") or {}
        rep.mtr_packet_loss = stats.get("loss")


# ---------------------------------------------------------------------------
# Diagnóstico
# ---------------------------------------------------------------------------
def diagnose(target: str, regions: list[str], token: str | None = None) -> dict[str, Report]:
    client = GP(token=token)
    reports: dict[str, Report] = {}
    locs = [{"magic": r} for r in regions]

    print(f"[+] HTTPS GET {target} em {len(regions)} regiões...")
    http_res = client.run({
        "type": "http",
        "target": target,
        "locations": locs,
        "measurementOptions": {
            "protocol": "HTTPS",
            "request": {"method": "GET", "path": "/", "host": target},
        },
        "limit": len(regions),
    })
    parse_http(http_res, reports)

    print(f"[+] DNS A {target} em {len(regions)} regiões...")
    dns_res = client.run({
        "type": "dns",
        "target": target,
        "locations": locs,
        "measurementOptions": {"query": {"type": "A"}, "protocol": "UDP"},
        "limit": len(regions),
    })
    parse_dns(dns_res, reports)

    degraded = [k for k, v in reports.items() if v.verdict != "OK"]
    if degraded:
        print(f"[+] MTR em {len(degraded)} regiões degradadas...")
        try:
            mtr_res = client.run({
                "type": "mtr",
                "target": target,
                "locations": locs,
                "measurementOptions": {"protocol": "ICMP", "packets": 3},
                "limit": len(regions),
            })
            parse_mtr(mtr_res, reports)
        except Exception as e:
            print(f"    (mtr ignorado: {e})")

    # Detecta DNS divergente (GeoDNS ou poisoning)
    all_ips = {ip for r in reports.values() for ip in r.dns_resolved_ips}
    if len(all_ips) > 1:
        for r in reports.values():
            if r.dns_resolved_ips and set(r.dns_resolved_ips) != all_ips:
                r.notes.append(f"DNS divergente: {r.dns_resolved_ips}")

    return reports


# ---------------------------------------------------------------------------
# Saída
# ---------------------------------------------------------------------------
ICONS = {
    "OK": "[OK]      ", "TIMEOUT": "[TIMEOUT] ", "BLOCKED": "[BLOCKED] ",
    "DNS_FAIL": "[DNS]     ", "TLS_FAIL": "[TLS]     ", "ERROR": "[ERROR]   ",
    "UNKNOWN": "[?]       ",
}


def print_report(target: str, reports: dict[str, Report]):
    print("\n" + "=" * 78)
    print(f" RELATÓRIO — {target}")
    print("=" * 78)
    for region, rep in sorted(reports.items()):
        line = f"{ICONS.get(rep.verdict, '[?]')}{region:<30}"
        if rep.http_status is not None:
            line += f" HTTP {rep.http_status}"
        if rep.http_total_ms is not None:
            line += f"  total={rep.http_total_ms:.0f}ms"
            if rep.http_tls_ms is not None:
                line += f" tls={rep.http_tls_ms:.0f}ms"
        if rep.http_resolved_ip:
            line += f"  ip={rep.http_resolved_ip}"
        print(line)
        for note in rep.notes:
            print(f"      -> {note}")
        if rep.mtr_last_hop and rep.verdict != "OK":
            loss = f" (loss={rep.mtr_packet_loss}%)" if rep.mtr_packet_loss is not None else ""
            print(f"      -> último hop MTR: {rep.mtr_last_hop}{loss}")
    print("=" * 78)
    ok = sum(1 for r in reports.values() if r.verdict == "OK")
    print(f" Resumo: {ok}/{len(reports)} regiões OK")
    if ok >= len(reports) * 0.7:
        print(" >>> Site está NO AR. Se ping estava falhando, é ICMP filtrado, não outage.")
    elif ok == 0:
        print(" >>> Nenhuma região conseguiu — alvo provavelmente realmente indisponível.")
    print()


def save_json(reports: dict[str, Report], path: str):
    data = {k: asdict(v) for k, v in reports.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON salvo em {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Monitor multi-região via GlobalPing")
    ap.add_argument("target", help="domínio alvo, ex: odontoprev.com.br")
    ap.add_argument("--regions", nargs="+", default=DEFAULT_REGIONS)
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--token", default=os.environ.get("GLOBALPING_TOKEN"))
    args = ap.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").strip("/")
    try:
        reports = diagnose(target, args.regions, token=args.token)
    except Exception as e:
        print(f"[!] erro: {e}", file=sys.stderr)
        sys.exit(1)

    print_report(target, reports)
    if args.json_out:
        save_json(reports, args.json_out)


if __name__ == "__main__":
    main()
