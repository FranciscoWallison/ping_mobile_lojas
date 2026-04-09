"""
globalping_monitor.py
---------------------
PoC de validação multi-região de um alvo (uptime, bloqueio geo, diagnóstico).

Usa a API pública do GlobalPing (https://api.globalping.io/v1).
Sem API key: ~250 testes/hora por IP. Com API key (OAuth) o limite sobe.
"""

from __future__ import annotations

import time
import json
from dataclasses import dataclass, field, asdict
from typing import Any
import requests


GLOBALPING_API = "https://api.globalping.io/v1/measurements"
POLL_INTERVAL = 1.0          # segundos entre GETs enquanto a medição não finaliza
POLL_TIMEOUT = 60            # segundos até desistir de esperar a medição


# ---------------------------------------------------------------------------
# Cliente GlobalPing
# ---------------------------------------------------------------------------
class GlobalPingClient:
    def __init__(self, api_token: str | None = None, timeout: int = 30):
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "gp-monitor-poc/0.1",
        })
        if api_token:
            self.session.headers["Authorization"] = f"Bearer {api_token}"
        self.timeout = timeout

    def create(self, payload: dict) -> str:
        r = self.session.post(GLOBALPING_API, json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["id"]

    def fetch(self, measurement_id: str) -> dict:
        r = self.session.get(f"{GLOBALPING_API}/{measurement_id}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def run(self, payload: dict) -> dict:
        """Cria medição e faz polling até finalizar (ou timeout)."""
        mid = self.create(payload)
        start = time.time()
        while True:
            data = self.fetch(mid)
            if data.get("status") == "finished":
                return data
            if time.time() - start > POLL_TIMEOUT:
                raise TimeoutError(f"medição {mid} não finalizou em {POLL_TIMEOUT}s")
            time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Modelo de resultado normalizado
# ---------------------------------------------------------------------------
@dataclass
class RegionReport:
    region: str
    probe_country: str = ""
    probe_city: str = ""
    probe_asn: str = ""
    # HTTP
    http_status: int | None = None
    http_total_ms: float | None = None
    http_dns_ms: float | None = None
    http_tcp_ms: float | None = None
    http_tls_ms: float | None = None
    http_first_byte_ms: float | None = None
    http_resolved_ip: str = ""
    http_tls_subject: str = ""
    http_tls_issuer: str = ""
    # DNS
    dns_resolved_ips: list[str] = field(default_factory=list)
    dns_error: str = ""
    # MTR / rota
    mtr_last_hop: str = ""
    mtr_packet_loss: float | None = None
    # Classificação final
    verdict: str = "UNKNOWN"   # OK / TIMEOUT / BLOCKED / DNS_FAIL / TLS_FAIL / ERROR
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsers para cada tipo de medição
# ---------------------------------------------------------------------------
def _probe_meta(probe: dict) -> dict:
    p = probe.get("probe", {})
    return {
        "probe_country": p.get("country", ""),
        "probe_city": p.get("city", ""),
        "probe_asn": str(p.get("asn", "")),
    }


def parse_http(result: dict, reports: dict[str, RegionReport], region_key: str):
    """Extrai status, timings, TLS e IP resolvido de cada probe."""
    for probe in result.get("results", []):
        key = _region_label(probe, region_key)
        rep = reports.setdefault(key, RegionReport(region=key))
        rep.__dict__.update(_probe_meta(probe))

        r = probe.get("result", {})
        raw = r.get("rawOutput", "") or ""

        # Timings (presentes em http measurements)
        timings = r.get("timings", {}) or {}
        rep.http_dns_ms = timings.get("dns")
        rep.http_tcp_ms = timings.get("tcp")
        rep.http_tls_ms = timings.get("tls")
        rep.http_first_byte_ms = timings.get("firstByte")
        rep.http_total_ms = timings.get("total")

        rep.http_status = r.get("statusCode")
        rep.http_resolved_ip = r.get("resolvedAddress", "") or ""

        tls = r.get("tls") or {}
        if tls:
            subj = tls.get("subject", {}) or {}
            issu = tls.get("issuer", {}) or {}
            rep.http_tls_subject = subj.get("CN", "")
            rep.http_tls_issuer = issu.get("CN", "")

        # Classificação preliminar
        if r.get("status") == "failed" or rep.http_status is None:
            if "timeout" in raw.lower() or "timed out" in raw.lower():
                rep.verdict = "TIMEOUT"
                rep.notes.append("HTTP timeout na borda do probe")
            elif "tls" in raw.lower() or "ssl" in raw.lower() or "certificate" in raw.lower():
                rep.verdict = "TLS_FAIL"
                rep.notes.append(raw.strip().splitlines()[0] if raw else "TLS error")
            elif "getaddrinfo" in raw.lower() or "enotfound" in raw.lower():
                rep.verdict = "DNS_FAIL"
                rep.notes.append("DNS não resolveu no probe")
            else:
                rep.verdict = "ERROR"
                rep.notes.append(raw.strip().splitlines()[0][:200] if raw else "erro desconhecido")
        elif 200 <= rep.http_status < 400:
            rep.verdict = "OK"
        elif rep.http_status in (403, 451):
            rep.verdict = "BLOCKED"
            rep.notes.append(f"HTTP {rep.http_status} — provável bloqueio geo/WAF")
        elif rep.http_status >= 500:
            rep.verdict = "ERROR"
            rep.notes.append(f"HTTP {rep.http_status}")
        else:
            rep.notes.append(f"HTTP {rep.http_status}")


def parse_dns(result: dict, reports: dict[str, RegionReport], region_key: str):
    """Captura IPs resolvidos por região — compara com http_resolved_ip pra pegar GeoDNS/poisoning."""
    for probe in result.get("results", []):
        key = _region_label(probe, region_key)
        rep = reports.setdefault(key, RegionReport(region=key))
        rep.__dict__.update(_probe_meta(probe))

        r = probe.get("result", {})
        answers = r.get("answers") or []
        ips = [a.get("value") for a in answers if a.get("type") in ("A", "AAAA")]
        rep.dns_resolved_ips = [ip for ip in ips if ip]

        if r.get("status") == "failed":
            rep.dns_error = (r.get("rawOutput", "") or "").strip().splitlines()[-1][:200]


def parse_mtr(result: dict, reports: dict[str, RegionReport], region_key: str):
    """Extrai último hop alcançado e packet loss — útil pra identificar null-route regional."""
    for probe in result.get("results", []):
        key = _region_label(probe, region_key)
        rep = reports.setdefault(key, RegionReport(region=key))
        rep.__dict__.update(_probe_meta(probe))

        r = probe.get("result", {})
        hops = r.get("hops") or []
        if not hops:
            continue
        last = hops[-1]
        rep.mtr_last_hop = last.get("resolvedAddress") or last.get("resolvedHostname") or ""
        stats = last.get("stats") or {}
        rep.mtr_packet_loss = stats.get("loss")


def _region_label(probe: dict, fallback: str) -> str:
    p = probe.get("probe", {})
    city = p.get("city", "")
    country = p.get("country", "")
    if city and country:
        return f"{city}, {country}"
    return country or fallback


# ---------------------------------------------------------------------------
# Diagnóstico completo
# ---------------------------------------------------------------------------
def diagnose(target: str, regions: list[str], api_token: str | None = None) -> dict[str, RegionReport]:
    """
    Roda HTTP + DNS + MTR em cada região e retorna relatórios normalizados.
    `target` deve ser um domínio (ex: "exemplo.com") — sem https://.
    `regions` usa o campo 'magic' do GlobalPing: "BR", "Germany", "us-east-1", "São Paulo", etc.
    """
    client = GlobalPingClient(api_token=api_token)
    reports: dict[str, RegionReport] = {}

    # 1) HTTP — uptime + timings + TLS + IP resolvido pelo probe
    http_payload = {
        "type": "http",
        "target": target,
        "locations": [{"magic": r} for r in regions],
        "measurementOptions": {
            "protocol": "HTTPS",
            "request": {"method": "GET", "path": "/", "host": target},
        },
        "limit": len(regions),
    }
    print(f"[+] HTTPS GET {target} em {len(regions)} regiões...")
    http_res = client.run(http_payload)
    parse_http(http_res, reports, region_key="http")

    # 2) DNS — resolução A a partir de cada região (detecta GeoDNS/poisoning)
    dns_payload = {
        "type": "dns",
        "target": target,
        "locations": [{"magic": r} for r in regions],
        "measurementOptions": {"query": {"type": "A"}, "protocol": "UDP"},
        "limit": len(regions),
    }
    print(f"[+] DNS A {target} em {len(regions)} regiões...")
    dns_res = client.run(dns_payload)
    parse_dns(dns_res, reports, region_key="dns")

    # 3) MTR — só faz sentido quando HTTP falhou ou o destino está degradado
    degraded = [r.region for r in reports.values() if r.verdict not in ("OK",)]
    if degraded:
        print(f"[+] MTR em {len(degraded)} regiões degradadas...")
        mtr_payload = {
            "type": "mtr",
            "target": target,
            "locations": [{"magic": r} for r in regions],
            "measurementOptions": {"protocol": "ICMP", "packets": 3},
            "limit": len(regions),
        }
        try:
            mtr_res = client.run(mtr_payload)
            parse_mtr(mtr_res, reports, region_key="mtr")
        except Exception as e:
            print(f"    (mtr ignorado: {e})")

    # 4) Pós-análise: detecta divergência DNS (possível GeoDNS ou DNS hijack)
    all_ips = {ip for r in reports.values() for ip in r.dns_resolved_ips}
    if len(all_ips) > 1:
        for r in reports.values():
            if r.dns_resolved_ips and set(r.dns_resolved_ips) != all_ips:
                r.notes.append(f"DNS divergente: {r.dns_resolved_ips} (pode ser GeoDNS legítimo)")

    return reports


# ---------------------------------------------------------------------------
# Saída — relatório humano + JSON
# ---------------------------------------------------------------------------
VERDICT_ICONS = {
    "OK": "✅",
    "TIMEOUT": "⏱️ ",
    "BLOCKED": "🚫",
    "DNS_FAIL": "🧭",
    "TLS_FAIL": "🔐",
    "ERROR": "❌",
    "UNKNOWN": "❓",
}


def print_report(target: str, reports: dict[str, RegionReport]) -> None:
    print("\n" + "=" * 78)
    print(f" RELATÓRIO — {target}")
    print("=" * 78)
    for region, rep in sorted(reports.items()):
        icon = VERDICT_ICONS.get(rep.verdict, "❓")
        line = f"{icon} {rep.verdict:<9} {region:<30}"
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
            print(f"      └─ {note}")
        if rep.mtr_last_hop and rep.verdict != "OK":
            loss = f" (loss={rep.mtr_packet_loss}%)" if rep.mtr_packet_loss is not None else ""
            print(f"      └─ último hop MTR: {rep.mtr_last_hop}{loss}")
    print("=" * 78)
    ok = sum(1 for r in reports.values() if r.verdict == "OK")
    print(f" Resumo: {ok}/{len(reports)} regiões OK\n")


def save_json(reports: dict[str, RegionReport], path: str) -> None:
    data = {k: asdict(v) for k, v in reports.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] resultado salvo em {path}")
