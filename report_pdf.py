"""
report_pdf.py
-------------
Gera um relatório PDF de monitoramento multi-região via GlobalPing.

Uso:
    # Modo 1: a partir de um JSON já gerado (--json)
    python report_pdf.py --json resultado.json
    python report_pdf.py --json resultado.json --output relatorio.pdf --author "Outro Nome"

    # Modo 2: roda o diagnóstico na hora e gera o PDF
    python report_pdf.py odontoprev.com.br
    python report_pdf.py odontoprev.com.br --regions BR US DE JP --output diag.pdf
    python report_pdf.py odontoprev.com.br --token $GLOBALPING_TOKEN
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from fpdf import FPDF, XPos, YPos

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
AUTHOR_DEFAULT = "Francisco Wallison"

DEFAULT_REGIONS = [
    "BR", "US", "DE", "GB", "JP", "SG", "AU", "ZA", "IN", "RU", "CN", "IR",
]

VERDICT_COLORS: dict[str, tuple[int, int, int]] = {
    "OK":       (200, 240, 200),
    "TIMEOUT":  (255, 220, 150),
    "BLOCKED":  (255, 180, 180),
    "DNS_FAIL": (255, 240, 150),
    "TLS_FAIL": (220, 180, 255),
    "ERROR":    (255, 160, 160),
    "UNKNOWN":  (210, 210, 210),
}

VERDICT_LABELS = {
    "OK":       "OK",
    "TIMEOUT":  "TIMEOUT",
    "BLOCKED":  "BLOQUEADO",
    "DNS_FAIL": "FALHA DNS",
    "TLS_FAIL": "FALHA TLS",
    "ERROR":    "ERRO",
    "UNKNOWN":  "DESCONHECIDO",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe(text) -> str:
    """Converte para latin-1 substituindo caracteres nao suportados pela fonte Helvetica."""
    return str(text or "").encode("latin-1", errors="replace").decode("latin-1")


def _fmt_ms(value) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.0f} ms"
    except (TypeError, ValueError):
        return str(value)


def load_reports_from_json(path: str) -> tuple[str, list[dict]]:
    """Carrega relatórios de um arquivo JSON gerado por save_json()."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    reports = [{"region": k, **v} for k, v in raw.items()]
    target = Path(path).stem.replace("_report", "").replace("_relatorio", "")
    return target, reports


def load_reports_from_diagnosis(
    target: str,
    regions: list[str],
    api_token: str | None = None,
) -> list[dict]:
    """Roda diagnóstico ao vivo e retorna lista de dicts de relatório."""
    try:
        from globalping_monitor import diagnose
        from dataclasses import asdict
    except ImportError:
        print("[!] globalping_monitor.py nao encontrado no mesmo diretório.", file=sys.stderr)
        sys.exit(1)

    reports_obj = diagnose(target, regions, api_token=api_token)
    return [{"region": k, **asdict(v)} for k, v in reports_obj.items()]


# ---------------------------------------------------------------------------
# Seções do PDF
# ---------------------------------------------------------------------------
def _draw_header(pdf: FPDF, target: str, author: str, generated_at: str) -> None:
    """Cabeçalho da primeira página."""
    # Linha colorida no topo
    pdf.set_fill_color(30, 60, 120)
    pdf.rect(0, 0, 210, 18, style="F")

    pdf.set_y(4)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, _safe("Relatorio de Monitoramento Multi-Regiao"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_text_color(0, 0, 0)

    pdf.set_y(24)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, _safe(f"Alvo: {target}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _safe(f"Autor: {author}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 6, _safe(f"Gerado em: {generated_at}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(4)
    pdf.set_draw_color(30, 60, 120)
    pdf.set_line_width(0.5)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)


def _draw_summary_table(pdf: FPDF, reports: list[dict]) -> None:
    """Tabela resumo com uma linha por região."""
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _safe("Resumo por Regiao"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # Cabeçalho da tabela
    col_w = [55, 26, 18, 32, 49]  # total = 180mm
    headers = ["Regiao", "Veredito", "HTTP", "Latencia (ms)", "IP Resolvido"]

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(30, 60, 120)
    pdf.set_text_color(255, 255, 255)
    for w, h in zip(col_w, headers):
        pdf.cell(w, 8, _safe(h), border=1, fill=True, align="C")
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    # Linhas de dados
    pdf.set_font("Helvetica", "", 8)
    sorted_reports = sorted(reports, key=lambda r: r.get("region", ""))
    for i, rep in enumerate(sorted_reports):
        verdict = rep.get("verdict", "UNKNOWN")
        color = VERDICT_COLORS.get(verdict, (210, 210, 210))
        # Alterna fundo branco / cor do veredito
        bg = color if i % 2 == 0 else tuple(min(255, c + 20) for c in color)
        pdf.set_fill_color(*bg)

        http_s = str(rep.get("http_status") or "-")
        lat = _fmt_ms(rep.get("http_total_ms"))
        ip = rep.get("http_resolved_ip") or "-"
        label = VERDICT_LABELS.get(verdict, verdict)

        row = [rep.get("region", ""), label, http_s, lat, ip]
        for w, val in zip(col_w, row):
            pdf.cell(w, 7, _safe(val), border=1, fill=True, align="C" if w < 40 else "L")
        pdf.ln()

    pdf.ln(5)


def _draw_detail_section(pdf: FPDF, reports: list[dict]) -> None:
    """Detalhamento técnico por região."""
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _safe("Detalhamento por Regiao"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    sorted_reports = sorted(reports, key=lambda r: r.get("region", ""))
    for rep in sorted_reports:
        # Verifica espaço na página
        if pdf.get_y() > 250:
            pdf.add_page()

        verdict = rep.get("verdict", "UNKNOWN")
        color = VERDICT_COLORS.get(verdict, (210, 210, 210))
        pdf.set_fill_color(*color)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, _safe(f"  {rep.get('region', '')}  [{VERDICT_LABELS.get(verdict, verdict)}]"),
                 border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 8)
        label_w = 52
        val_w = 128

        fields = [
            ("Pais/Cidade do probe", f"{rep.get('probe_city','')} {rep.get('probe_country','')}".strip()),
            ("ASN do probe",         rep.get("probe_asn")),
            ("HTTP Status",          rep.get("http_status")),
            ("Latencia total",       _fmt_ms(rep.get("http_total_ms"))),
            ("Resolucao DNS",        _fmt_ms(rep.get("http_dns_ms"))),
            ("Conexao TCP",          _fmt_ms(rep.get("http_tcp_ms"))),
            ("Handshake TLS",        _fmt_ms(rep.get("http_tls_ms"))),
            ("Primeiro byte (TTFB)", _fmt_ms(rep.get("http_first_byte_ms"))),
            ("IP resolvido",         rep.get("http_resolved_ip")),
            ("Cert TLS (CN)",        rep.get("http_tls_subject")),
            ("Emissor TLS",          rep.get("http_tls_issuer")),
            ("IPs DNS",              ", ".join(rep.get("dns_resolved_ips") or []) or None),
            ("Erro DNS",             rep.get("dns_error")),
            ("Ultimo hop MTR",       rep.get("mtr_last_hop")),
            ("Perda pacotes MTR",    f"{rep.get('mtr_packet_loss')}%" if rep.get("mtr_packet_loss") is not None else None),
        ]

        for label, value in fields:
            if not value or str(value).strip() in ("", "None", "0", "0%"):
                continue
            if pdf.get_y() > 275:
                pdf.add_page()
            pdf.set_fill_color(248, 248, 252)
            pdf.cell(label_w, 6, _safe(f"  {label}:"), border="LB", fill=True)
            pdf.cell(val_w, 6, _safe(str(value)), border="RB", fill=False, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Observações (multi_cell para textos longos)
        notes = rep.get("notes") or []
        if notes:
            if pdf.get_y() > 270:
                pdf.add_page()
            pdf.set_fill_color(248, 248, 252)
            pdf.cell(label_w, 6, _safe("  Observacoes:"), border="LB", fill=True)
            note_text = "; ".join(notes)
            x = pdf.get_x()
            y = pdf.get_y()
            pdf.multi_cell(val_w, 6, _safe(note_text), border="RB")
            _ = x, y  # referência para evitar warning

        pdf.ln(3)


def _draw_verdict_stats(pdf: FPDF, reports: list[dict]) -> None:
    """Tabela de estatísticas por veredito."""
    if pdf.get_y() > 230:
        pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _safe("Estatisticas por Veredito"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    counts: dict[str, int] = {}
    for r in reports:
        v = r.get("verdict", "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
    total = len(reports)

    col_w = [60, 40, 40]
    headers = ["Veredito", "Quantidade", "Percentual"]
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(30, 60, 120)
    pdf.set_text_color(255, 255, 255)
    for w, h in zip(col_w, headers):
        pdf.cell(w, 7, _safe(h), border=1, fill=True, align="C")
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    pdf.set_font("Helvetica", "", 9)
    for verdict, count in sorted(counts.items(), key=lambda x: -x[1]):
        color = VERDICT_COLORS.get(verdict, (210, 210, 210))
        pdf.set_fill_color(*color)
        pct = f"{count / total * 100:.0f}%"
        row = [VERDICT_LABELS.get(verdict, verdict), str(count), pct]
        for w, val in zip(col_w, row):
            pdf.cell(w, 7, _safe(val), border=1, fill=True, align="C")
        pdf.ln()

    # Total
    pdf.set_fill_color(200, 200, 220)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(col_w[0], 7, _safe("TOTAL"), border=1, fill=True, align="C")
    pdf.cell(col_w[1], 7, _safe(str(total)), border=1, fill=True, align="C")
    pdf.cell(col_w[2], 7, _safe("100%"), border=1, fill=True, align="C")
    pdf.ln()
    pdf.ln(5)


def _build_conclusion(reports: list[dict], target: str) -> str:
    """Gera texto de conclusão automático em português."""
    total = len(reports)
    counts: dict[str, int] = {}
    for r in reports:
        v = r.get("verdict", "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
    ok = counts.get("OK", 0)

    lines = [
        f"Foram testadas {total} regioes para o alvo '{target}'.",
        f"{ok} de {total} regioes responderam com sucesso (HTTP 2xx/3xx).",
    ]

    if counts.get("TIMEOUT"):
        lines.append(
            f"{counts['TIMEOUT']} regiao(oes) apresentaram timeout HTTP. "
            "Isso pode indicar filtragem de pacotes por firewall/WAF ou indisponibilidade real nessas regioes. "
            "Recomenda-se verificar com MTR se o roteamento chega ao destino."
        )
    if counts.get("BLOCKED"):
        lines.append(
            f"{counts['BLOCKED']} regiao(oes) receberam bloqueio geografico ou WAF (HTTP 403/451). "
            "O servidor esta acessivel mas recusa conexoes de determinadas origens."
        )
    if counts.get("DNS_FAIL"):
        lines.append(
            f"{counts['DNS_FAIL']} regiao(oes) apresentaram falha de resolucao DNS. "
            "O dominio pode nao estar propagado ou o servidor DNS pode estar inacessivel nessas regioes."
        )
    if counts.get("TLS_FAIL"):
        lines.append(
            f"{counts['TLS_FAIL']} regiao(oes) tiveram falha no handshake TLS. "
            "Possivel certificado invalido, expirado ou bloqueio de SNI."
        )
    if counts.get("ERROR"):
        lines.append(
            f"{counts['ERROR']} regiao(oes) retornaram erro HTTP (5xx). "
            "O servidor esta acessivel mas com problema interno."
        )

    if ok == total:
        lines.append(
            "CONCLUSAO: O servico esta disponivel globalmente em todas as regioes testadas. "
            "Nenhuma anomalia detectada."
        )
    elif ok == 0:
        lines.append(
            "ATENCAO: Nenhuma regiao obteve resposta HTTP valida. "
            "O alvo pode estar completamente indisponivel ou bloqueado."
        )
    elif ok >= total * 0.7:
        lines.append(
            f"CONCLUSAO: O servico esta majoritariamente disponivel ({ok}/{total} regioes OK). "
            "As falhas sao pontuais e podem ser causadas por politicas de firewall regionais."
        )
    else:
        lines.append(
            f"ATENCAO: Apenas {ok} de {total} regioes obtiveram resposta valida. "
            "Recomenda-se investigacao mais aprofundada nas regioes com falha."
        )

    return " ".join(lines)


def _draw_conclusion(pdf: FPDF, reports: list[dict], target: str) -> None:
    """Seção de conclusão."""
    if pdf.get_y() > 230:
        pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _safe("Conclusao"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    text = _build_conclusion(reports, target)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_fill_color(240, 245, 255)
    pdf.multi_cell(0, 6, _safe(text), border=1, fill=True)
    pdf.ln(5)


def _draw_footer(pdf: FPDF) -> None:
    """Rodapé em todas as páginas."""
    pdf.set_y(-12)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 5, _safe(f"Pagina {pdf.page_no()} — Relatorio gerado por gp-monitor"), align="C")
    pdf.set_text_color(0, 0, 0)


# ---------------------------------------------------------------------------
# Builder principal
# ---------------------------------------------------------------------------
def build_pdf(
    target: str,
    reports: list[dict],
    author: str,
    output_path: str,
) -> None:
    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 20, 15)
    pdf.add_page()

    _draw_header(pdf, target, author, generated_at)
    _draw_summary_table(pdf, reports)
    _draw_detail_section(pdf, reports)
    _draw_verdict_stats(pdf, reports)
    _draw_conclusion(pdf, reports, target)

    # Rodapé em todas as páginas
    for page in range(1, pdf.page_no() + 1):
        pdf.page = page
        _draw_footer(pdf)

    pdf.output(output_path)
    print(f"[+] PDF salvo em: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Gera relatório PDF de monitoramento multi-região via GlobalPing"
    )
    ap.add_argument(
        "target",
        nargs="?",
        help="Domínio alvo (ex: odontoprev.com.br). Obrigatório se --json não for fornecido.",
    )
    ap.add_argument(
        "--json",
        dest="json_path",
        help="Caminho para JSON gerado por gp_check.py ou run_check.py (--json resultado.json)",
    )
    ap.add_argument(
        "--output",
        dest="output",
        help="Nome do arquivo PDF de saída (default: <alvo>_relatorio.pdf)",
    )
    ap.add_argument(
        "--author",
        default=AUTHOR_DEFAULT,
        help=f"Nome do autor no relatório (default: {AUTHOR_DEFAULT})",
    )
    ap.add_argument(
        "--regions",
        nargs="+",
        default=DEFAULT_REGIONS,
        help="Regiões a testar quando --json não é usado",
    )
    ap.add_argument(
        "--token",
        default=os.environ.get("GLOBALPING_TOKEN"),
        help="Token OAuth do GlobalPing (opcional, lê GLOBALPING_TOKEN do ambiente)",
    )
    args = ap.parse_args()

    # Validação
    if not args.json_path and not args.target:
        ap.error(
            "Forneça um domínio alvo (ex: odontoprev.com.br) "
            "ou use --json resultado.json para carregar dados já coletados."
        )

    # Carrega dados
    if args.json_path:
        inferred_target, reports = load_reports_from_json(args.json_path)
        target = args.target or inferred_target
        print(f"[+] Carregando dados de: {args.json_path}")
    else:
        target = args.target.replace("https://", "").replace("http://", "").strip("/")
        print(f"[+] Executando diagnóstico para: {target}")
        reports = load_reports_from_diagnosis(target, args.regions, api_token=args.token)

    if not reports:
        print("[!] Nenhum dado para gerar o relatório.", file=sys.stderr)
        sys.exit(1)

    # Define nome do arquivo de saída
    if args.output:
        output_path = args.output
    else:
        safe_name = target.replace(".", "_").replace("/", "_")
        output_path = f"{safe_name}_relatorio.pdf"

    build_pdf(target, reports, author=args.author, output_path=output_path)


if __name__ == "__main__":
    main()
