# Monitor de Disponibilidade Multi-Região



Ferramenta de linha de comando para validar se uma URL está acessível em múltiplas regiões do mundo, usando a API pública do [GlobalPing](https://globalping.io). Ideal para diagnosticar bloqueios geográficos, problemas de DNS, falhas de TLS e indisponibilidade real.

---

## Por que isso importa?

**Ping (ICMP) não é suficiente para saber se um site está no ar.**

Muitos servidores bloqueiam o protocolo ICMP (o "ping" tradicional) por política de firewall, mas continuam respondendo requisições HTTP normalmente. Se você usar apenas ping para monitorar um site, pode receber falsos alertas de indisponibilidade.

Esta ferramenta valida o que realmente importa:

| O que testamos | Por que é importante |
|---|---|
| **HTTPS (HTTP GET)** | Prova que o servidor web está respondendo de verdade — não apenas "vivo na rede" |
| **DNS** | Confirma que o domínio resolve para o IP correto em cada região — detecta GeoDNS e envenenamento de DNS |
| **MTR (traceroute)** | Mostra exatamente onde o pacote morre quando há falha — se para no meio da rota ou chega ao destino |

---

## Glossário de Termos

### ASN (Autonomous System Number)
Identificador único de uma rede na internet. Cada provedor de internet, empresa de hospedagem ou big tech tem o seu. Exemplo: **ASN 15169 = Google**, **ASN 7628 = Claro Brasil**.

O Google Play valida URLs a partir dos seus próprios servidores (ASN 15169). Se o WAF de um servidor bloquear esse ASN, o Google não consegue acessar a URL — e a política de privacidade é rejeitada.

### WAF (Web Application Firewall)
Firewall na camada de aplicação que analisa o conteúdo das requisições HTTP. Pode bloquear por IP de origem, ASN, User-Agent, país, ou padrão de tráfego. Quando o WAF bloqueia, o cliente recebe HTTP 403 ou simplesmente não recebe resposta (timeout).

### GeoDNS
Técnica onde o servidor DNS retorna IPs diferentes dependendo da localização do requisitante. É legítimo em CDNs (para direcionar o usuário ao servidor mais próximo), mas pode ser confundido com envenenamento de DNS. O monitor detecta automaticamente quando IPs DNS divergem entre regiões.

### ICMP
Protocolo de controle de internet, usado pelo `ping`. Diferente do HTTP/TCP, ele não estabelece uma conexão — apenas envia um "eco" e espera resposta. É o primeiro protocolo a ser bloqueado por firewalls, por isso **timeout no ping não significa site fora do ar**.

### MTR (My TraceRoute)
Combina `ping` e `traceroute` em uma única ferramenta. Mostra cada "salto" (roteador) pelo qual o pacote passa até chegar ao destino, e a perda de pacotes em cada hop. Quando há timeout HTTP, o MTR revela se o problema está na rota (antes do servidor) ou no próprio servidor.

### TLS / HTTPS
TLS (Transport Layer Security) é o protocolo que cifra a comunicação HTTP — o "S" no HTTPS. O **handshake TLS** é a fase inicial da conexão onde certificado, chave e algoritmos são negociados. Falhas nessa fase (TLS_FAIL) indicam: certificado expirado, domínio divergente no certificado, ou bloqueio de SNI pelo firewall.

### TTFB (Time to First Byte)
Tempo entre o envio da requisição HTTP e o recebimento do primeiro byte da resposta. Inclui: resolução DNS + conexão TCP + handshake TLS + processamento no servidor. É o indicador mais fiel da performance percebida pelo usuário.

### Vereditos

| Veredito | Significado | O que fazer |
|---|---|---|
| ✅ **OK** | HTTP 2xx ou 3xx — site acessível nessa região | Nenhuma ação necessária |
| ⏱️ **TIMEOUT** | Sem resposta HTTP dentro do limite de tempo | Verificar se é ICMP filtrado (via MTR) ou queda real |
| 🚫 **BLOCKED** | HTTP 403 ou 451 — WAF ou bloqueio geográfico | Verificar política de acesso do servidor / CDN |
| 🧭 **DNS_FAIL** | DNS não resolveu o domínio nessa região | Verificar propagação DNS ou envenenamento |
| 🔐 **TLS_FAIL** | Falha no handshake TLS | Verificar validade do certificado e configuração SNI |
| ❌ **ERROR** | HTTP 5xx — servidor acessível mas com erro interno | Verificar logs do servidor |
| ❓ **UNKNOWN** | Falha não classificada | Verificar rawOutput no JSON de saída |

---

## Instalação

```bash
# Requisito mínimo (apenas para diagnóstico)
pip install requests

# Completo (com geração de PDF)
pip install requests fpdf2

# Ou via requirements.txt
pip install -r requirements.txt
```

**Token GlobalPing (opcional):** sem token, o limite é ~250 testes/hora por IP. Com token OAuth, o limite aumenta significativamente.

```bash
export GLOBALPING_TOKEN=seu_token_aqui
```

---

## Scripts Disponíveis

### `gp_check.py` — Diagnóstico standalone (recomendado para uso rápido)

Arquivo único, sem dependências além de `requests`. Inclui tudo internamente.

```bash
# Diagnóstico básico (10 regiões padrão)
python gp_check.py odontoprev.com.br

# Regiões específicas
python gp_check.py odontoprev.com.br --regions BR US DE JP SG

# Salvar resultado em JSON
python gp_check.py odontoprev.com.br --json resultado.json

# Com token para maior rate limit
python gp_check.py odontoprev.com.br --token $GLOBALPING_TOKEN

# Combinando opções
python gp_check.py meusite.com.br --regions BR US DE --json saida.json --token $GLOBALPING_TOKEN
```

**Regiões padrão:** BR, US, DE, GB, JP, SG, AU, ZA, IN, FR

---

### `run_check.py` — Diagnóstico com módulo separado

Usa `globalping_monitor.py` como biblioteca. Mesmas opções do `gp_check.py`, mas com lista de regiões estendida (inclui RU, CN, IR para detectar censura).

```bash
python run_check.py odontoprev.com.br
python run_check.py odontoprev.com.br --regions BR US DE --json resultado.json
```

**Regiões padrão:** BR, US, DE, GB, JP, SG, AU, ZA, IN, RU, CN, IR

---

### `validate_odontoprev.py` — Caso de uso específico

Script pré-configurado para testar a hipótese "odontoprev.com.br bloqueia ICMP mas aceita HTTPS". Roda sem argumentos, salva em `odontoprev_report.json`.

```bash
python validate_odontoprev.py
```

---

### `report_pdf.py` — Gerador de Relatório PDF

Gera um PDF completo com cabeçalho (autor, data/hora), tabela resumo colorida, detalhamento por região e conclusão automática.

```bash
# Modo 1: a partir de um JSON já gerado
python report_pdf.py --json resultado.json
python report_pdf.py --json resultado.json --output meu_relatorio.pdf
python report_pdf.py --json resultado.json --author "Seu Nome" --output relatorio.pdf

# Modo 2: roda o diagnóstico e gera o PDF diretamente
python report_pdf.py odontoprev.com.br
python report_pdf.py odontoprev.com.br --regions BR US DE JP --output diag.pdf
python report_pdf.py odontoprev.com.br --token $GLOBALPING_TOKEN

# Fluxo completo recomendado (arquivos salvos em output/)
python gp_check.py meusite.com --json resultado.json
python report_pdf.py --json output/resultado.json
```

**Conteúdo do PDF:**
- Cabeçalho: autor, alvo, data e hora de geração
- Tabela resumo: região, veredito (colorido), HTTP status, latência total, IP resolvido
- Detalhamento: DNS ms, TCP ms, TLS ms, TTFB ms, certificado TLS, IPs DNS, último hop MTR, ASN do probe, observações
- Estatísticas: contagem e percentual por veredito
- Conclusão: análise automática em português

---

## Flag `--regions` — Como Especificar Regiões

O GlobalPing usa um campo "magic" flexível para identificar regiões:

| Formato | Exemplos | Descrição |
|---|---|---|
| Código de país | `BR`, `US`, `DE`, `JP` | Seleciona qualquer probe naquele país |
| Nome de cidade | `"Sao Paulo"`, `"New York"`, `Tokyo` | Probe na cidade específica |
| Nome de continente | `Europe`, `Asia`, `"South America"` | Qualquer probe no continente |
| Região de nuvem | `aws-us-east-1`, `gcp-us-central1` | Probe em região de cloud específica |

```bash
# Teste global básico
--regions BR US DE GB JP SG AU

# Detectar censura/bloqueio geopolítico
--regions CN IR RU TR SA EG

# Validação para lojas de apps (regiões que Google/Apple usam)
--regions US GB DE JP AU SG

# Cobertura América Latina
--regions BR AR CL CO MX PE
```

> **Dica:** Se `--regions CN` não retornar nada, tente `Asia` ou `Hong Kong` — probes em países com censura intensa são escassos.

---

## Como Interpretar os Resultados

### TIMEOUT em algumas regiões, OK em outras

```
✅ OK       Sao Paulo, BR    HTTP 200  total=233ms  ip=201.59.24.24
✅ OK       London, GB       HTTP 200  total=1010ms ip=201.59.24.24
⏱️ TIMEOUT  New York, US
⏱️ TIMEOUT  Singapore, SG
```

**Interpretação:** O servidor está no ar. O WAF está bloqueando conexões de faixas de IP específicas. O MTR confirmará se o pacote chega ao destino e é descartado lá.

**Impacto prático:** O Google Play, ao validar um link de política de privacidade, vem de servidores americanos (ASN 15169 - Google). Se esses IPs estiverem bloqueados, a validação falha e o app é rejeitado.

---

### DNS divergente entre regiões

```
✅ OK   Tokyo, JP     ip=104.21.10.1   DNS: [104.21.10.1]
✅ OK   Sao Paulo, BR ip=172.67.5.2   DNS: [172.67.5.2]
       └─ DNS divergente: [172.67.5.2] (pode ser GeoDNS legítimo)
```

**Interpretação:** O servidor usa GeoDNS (CDN como Cloudflare ou AWS CloudFront), que é legítimo. IPs diferentes por região = servidor mais próximo para cada usuário. Preocupação apenas se o IP divergente não pertencer à mesma organização.

---

### BLOCKED (HTTP 403)

```
🚫 BLOCKED  Frankfurt, DE    HTTP 403
      └─ HTTP 403 — provável bloqueio/WAF
```

**Interpretação:** O servidor está no ar, mas recusa conexões dessa origem. Pode ser bloqueio por país, ASN, User-Agent, ou política do WAF.

---

## Uso com Docker

```bash
# Build da imagem
docker build -t gp-monitor .

# Diagnóstico básico
docker run gp-monitor odontoprev.com.br

# Com regiões específicas
docker run gp-monitor odontoprev.com.br --regions BR US DE JP

# Salvar JSON em diretório local (volume)
mkdir output
docker run -v $(pwd)/output:/app/output gp-monitor odontoprev.com.br --json /app/output/resultado.json

# Com token (maior rate limit)
docker run -e GLOBALPING_TOKEN=$GLOBALPING_TOKEN gp-monitor odontoprev.com.br

# Gerar PDF dentro do container
docker run --entrypoint python \
  -v $(pwd)/output:/app/output \
  gp-monitor report_pdf.py odontoprev.com.br --output /app/output/relatorio.pdf
```

---

## Rate Limiting

| Situação | Limite aproximado |
|---|---|
| Sem token | ~250 probes/hora por IP |
| Com token OAuth | Muito maior (ver docs GlobalPing) |
| Cada `diagnose()` | 2–3 chamadas de API (HTTP + DNS + MTR condicional) |
| Cada chamada | `limit=N` probes simultâneos (N = número de regiões) |

---

## Estrutura do Projeto

```
files/
├── globalping_monitor.py    # Biblioteca principal: cliente API, parsers, RegionReport
├── gp_check.py              # CLI standalone (arquivo único, sem imports externos)
├── run_check.py             # CLI que usa globalping_monitor como módulo
├── validate_odontoprev.py   # Script específico para odontoprev.com.br
├── report_pdf.py            # Gerador de relatório PDF (autor, data/hora, tabelas)
├── output/                  # Saídas geradas (JSONs e PDFs) — ignorada pelo git
│   └── .gitkeep             # Mantém a pasta no repositório mesmo vazia
├── requirements.txt         # Dependências Python: requests, fpdf2
├── Dockerfile               # Container Docker com entrypoint gp_check.py
├── .gitignore               # Ignora output/*.json e output/*.pdf
├── .dockerignore            # Exclui arquivos desnecessários do contexto Docker
└── README.md                # Esta documentação
```

---

## Próximos Passos Possíveis

1. **Alertas automáticos** — enviar notificação por e-mail ou Slack quando uma região falha
2. **Agendamento** — executar o monitor em intervalos regulares (cron, GitHub Actions)
3. **Dashboard** — visualizar histórico de resultados em gráfico de disponibilidade
4. **Fingerprint TLS** — detectar MITM comparando o certificado entre regiões
5. **Análise de CDN** — identificar headers de CDN (Cloudflare, Akamai, AWS CloudFront) por região
6. **Modo watch** — repetir a verificação automaticamente a cada N minutos
