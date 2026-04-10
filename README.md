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

ASN é o "documento de identidade" de uma rede na internet. Cada organização que opera uma rede de grande porte — provedores de internet, empresas de hospedagem, big techs, bancos, operadoras — recebe um número único chamado ASN, emitido pela IANA (Internet Assigned Numbers Authority) através de registros regionais como o LACNIC (América Latina) e ARIN (América do Norte).

**Como funciona na prática:**

Quando seu computador acessa um site, o pacote passa por vários roteadores. Cada roteador sabe para qual ASN encaminhar o tráfego usando um protocolo chamado BGP (Border Gateway Protocol). O BGP é essencialmente um mapa global que diz: "para chegar ao IP X, passe pelo ASN Y".

Todo ASN agrupa um conjunto de faixas de IPs (chamadas de prefixos). Por exemplo:
- O ASN 15169 (Google) agrupa faixas como `8.8.8.0/24`, `142.250.0.0/15`, entre centenas de outros
- O ASN 7628 (Claro Brasil) agrupa os IPs que a Claro entrega para seus clientes no Brasil

**ASNs relevantes para monitoramento:**

| ASN | Organização | Por que importa |
|---|---|---|
| 15169 | Google LLC | Google Play, Google Search, YouTube — valida URLs a partir daqui |
| 16509 | Amazon AWS | Servidores EC2, Lambda — muito bloqueado por WAFs |
| 8075 | Microsoft Azure | Teams, Office 365, Azure Functions |
| 14618 | Amazon / AWS | Outra faixa AWS, igualmente bloqueada |
| 36351 | SoftLayer (IBM) | Frequentemente na lista negra de WAFs |
| 7628 | Claro Brasil | ISP residencial/corporativo BR |
| 4230 | Oi Brasil | ISP residencial BR |
| 28573 | Claro / NET Brasil | Banda larga residencial BR |

**Por que WAFs bloqueiam determinados ASNs:**

IPs de grandes provedores de nuvem (Google, AWS, Azure) são conhecidos por hospedar bots, scrapers e ferramentas de ataque automatizado. WAFs com perfil conservador bloqueiam faixas inteiras de IPs de data center por padrão — mesmo que o tráfego legítimo (como o Google validando uma URL) venha do mesmo bloco.

**Como verificar o ASN de um IP:**

```bash
# Usando whois
whois 142.250.78.46

# Resultado mostra: OrgName: Google LLC, ASN: AS15169
```

**Impacto direto no seu caso:**

O Google Play valida URLs (política de privacidade, termos de uso) a partir de servidores com ASN 15169. Se o WAF da Odontoprev bloqueia requisições desse ASN — mesmo sem intenção — o Google recebe timeout e rejeita o link. O monitor confirmou exatamente isso: regiões com IPs de data center (Buffalo/US com ASN M247, Falkenstein/DE) receberam timeout, enquanto IPs de provedores comuns (ISPs residenciais e comerciais) respondem normalmente.

### WAF (Web Application Firewall)

Firewall na camada de aplicação que fica na frente do servidor web e analisa cada requisição HTTP antes de ela chegar ao sistema. Diferente de um firewall de rede comum (que bloqueia por IP/porta), o WAF entende o conteúdo das requisições — headers, corpo, cookies, User-Agent — e toma decisões baseadas nisso.

**Como o WAF decide o que bloquear:**

| Critério | Exemplo | Resposta típica |
|---|---|---|
| IP de origem | Faixas de IPs de data center | Timeout ou HTTP 403 |
| ASN | ASN 15169 (Google), ASN 36352 (HostPapa) | Timeout ou HTTP 403 |
| País/região | Bloquear acessos de fora do Brasil | HTTP 403 ou redirect |
| User-Agent | Bots, scrapers, crawlers | HTTP 403 ou CAPTCHA |
| Taxa de requisições | Muitas requisições por segundo | HTTP 429 ou bloqueio |
| Padrão de tráfego | Sequências suspeitas de URLs | HTTP 403 |

**Por que isso afeta validações de lojas de apps:**

O Google Play e a Apple App Store validam URLs (como política de privacidade) a partir dos seus próprios servidores em data centers americanos. Esses IPs pertencem a faixas conhecidas de provedores de nuvem — exatamente o tipo de tráfego que WAFs conservadores bloqueiam por padrão, por confundi-los com bots ou scrapers.

**Como o monitor detecta WAF:**

- `TIMEOUT` → WAF descartou o pacote sem responder (modo silencioso)
- `BLOCKED` → WAF respondeu com HTTP 403/451 (modo explícito)
- O MTR chega ao servidor, mas o HTTP não responde → o bloqueio acontece na camada de aplicação, não na rede

**Exemplos de WAFs comuns:**

- **Cloudflare** — muito comum em sites brasileiros; bloqueia por reputação de IP
- **AWS WAF** — usado com CloudFront e API Gateway
- **Akamai Kona** — comum em grandes empresas e bancos
- **F5 / NGINX App Protect** — infraestrutura on-premise
- **Imperva** — foco em proteção contra DDoS e bots

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
