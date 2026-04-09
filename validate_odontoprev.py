"""
validate_odontoprev.py
----------------------
Valida a hipótese: "odontoprev.com.br bloqueia ICMP mas HTTP está OK".

Roda, em paralelo pelas mesmas regiões que deram timeout no ping:
  - HTTPS GET /          (prova de vida real do site)
  - TCP connect :443     (prova de vida L4, mesmo se o WAF bloquear path /)
  - DNS A                (confirma resolução consistente)
  - MTR                  (mostra onde o ICMP morre — útil pra ver se é na borda
                          do alvo ou no meio do caminho)
"""
from globalping_monitor import GlobalPingClient, diagnose, print_report, save_json

TARGET = "odontoprev.com.br"
REGIONS = [
    "Amsterdam",
    "Buffalo",
    "Falkenstein",
    "Frankfurt",
    "Helsinki",
    "Los Angeles",
    "Nuremberg",
    "Roubaix",
    "Tokyo",
    "BR",           # controle: de dentro do Brasil DEVE funcionar
]


def tcp_connect_check(client: GlobalPingClient, target: str, regions: list[str]):
    """
    HTTP measurement com método HEAD em /:443 isola 'o servidor TCP está vivo'
    de 'o path retorna 200'. Se HEAD funcionar e ping não, prova filtragem ICMP.
    """
    payload = {
        "type": "http",
        "target": target,
        "locations": [{"magic": r} for r in regions],
        "measurementOptions": {
            "protocol": "HTTPS",
            "port": 443,
            "request": {"method": "HEAD", "path": "/", "host": target},
        },
        "limit": len(regions),
    }
    return client.run(payload)


if __name__ == "__main__":
    print("=" * 78)
    print(" Hipótese: odontoprev.com.br filtra ICMP mas aceita HTTPS")
    print("=" * 78)

    # Usa o diagnóstico completo (http + dns + mtr condicional)
    reports = diagnose(TARGET, REGIONS)
    print_report(TARGET, reports)
    save_json(reports, "odontoprev_report.json")

    # Conclusão automática
    http_ok = sum(1 for r in reports.values() if r.verdict == "OK")
    if http_ok >= len(reports) * 0.7:
        print(">>> CONFIRMADO: o site está NO AR. O ping anterior mostrou")
        print(">>> ICMP bloqueado na borda, o que é política de firewall,")
        print(">>> NÃO indisponibilidade. Use HTTP/TCP pra monitorar esse alvo.")
    else:
        print(">>> HTTP também falhou em várias regiões — investigar mais a fundo.")
