# Como identificar a pilha de rede de um site/API (CDN, WAF, F5, origem)

Guia para responder a duas perguntas que aparecem sempre que algo "dá 403 na minha máquina mas funciona na outra":

1. **O que está na frente deste site/API?** Cloudflare, Akamai, F5 BIG-IP, FortiWeb, IIS...
2. **Quem me bloqueou, e por quê?** A borda (CDN/WAF em nuvem), um appliance on-premise (F5) ou o próprio servidor da aplicação?

Sem saber a camada que respondeu, o chamado vai para o time errado. Um 403 do Cloudflare não se resolve no IIS, e um 403 do IIS não se resolve no painel do Cloudflare.

---

## 1. Modelo mental: as camadas

Uma requisição atravessa várias camadas, e **qualquer uma delas pode responder 403** antes de a próxima ver a requisição:

```
 Seu cliente (curl, Insomnia, app, navegador)
   │   IP de saída: casa, VPN, rede corporativa, data center
   ▼
 DNS ──────────── decide PARA ONDE você vai (CDN pública ou IP interno?)
   ▼
 Borda / CDN / WAF em nuvem ── Cloudflare, Akamai, CloudFront, Azure Front Door, Imperva
   │   bloqueia por IP, ASN, país, reputação, User-Agent, bot score, desafio JS
   ▼
 Appliance no datacenter ───── F5 BIG-IP (LTM + ASM/Advanced WAF), FortiWeb, NetScaler
   │   balanceia, aplica política WAF, pode descartar em silêncio (timeout)
   ▼
 Servidor de origem ────────── IIS/ASP.NET, nginx, Apache, Node, Kestrel
       pode negar por IP Restrictions, autenticação ou regra da aplicação
```

Nem todo site tem todas as camadas. Exemplos reais medidos em 14/10/2026:

| Alvo | Pilha detectada |
|---|---|
| `obrsos.odontosystem.com.br` | **Cloudflare** (borda) → **IIS / ASP.NET** (origem, serviço WCF `.svc`) |
| `odontoprev.com.br` | **F5 BIG-IP LTM + ASM/Advanced WAF + AVR** (datacenter próprio, IP da Telefônica) → **Nuxt/Node** (origem) |

---

## 2. Atalho: a ferramenta faz tudo isso

```bash
# Pilha de rede + quem bloqueia, a partir da SUA rede
python waf_detect.py odontoprev.com.br

# Reproduzindo exatamente uma chamada de API (mesmos parâmetros do curl)
python waf_detect.py https://obrsos.odontosystem.com.br/OSMarcacaoWS.svc/especialidades-localidade-redes-guia \
  -X POST -H "Content-Type: application/json" \
  -d '{"id_localidade":"9668","id_bairro":"0","redes":[{"id":20,"nome":"Rede Odonto System"}]}' \
  --perfis curl navegador insomnia okhttp

# Mesma análise em várias regiões do mundo (via GlobalPing)
python gp_check.py obrsos.odontosystem.com.br --regions BR US DE
```

O `waf_detect.py` executa os passos 3 a 7 deste guia e imprime:

- **Sua saída:** o IP e o ASN que o WAF enxerga.
- **DNS:** a resolução local comparada com a pública (detecta *split-horizon*) e a cadeia de CNAME.
- **ASN de cada IP do alvo:** mostra se a hospedagem é CDN em nuvem ou datacenter próprio.
- **Pilha detectada:** cada camada com a evidência que a identificou (header, cookie, CNAME, ASN).
- **Uma requisição por perfil de cliente:** curl, navegador, insomnia, postman, okhttp (Android), ios e python.
- **Quem bloqueou:** a camada que respondeu, o ID do evento (CF-RAY, Support ID, Reference #...) e o próximo passo.
- **IP visto pelo Cloudflare:** se o alvo usa Cloudflare, o IP e o PoP retornados por `/cdn-cgi/trace`.

O `gp_check.py`, o `run_check.py` e o `report_pdf.py` agora também mostram a **pilha de rede** e **quem bloqueou** em cada região.

> **Regra de ouro:** rode o `waf_detect.py` nas duas redes, por exemplo a sua máquina e a máquina do domínio, e compare as saídas. Se a pilha é a mesma e só o resultado muda, a regra depende do IP/rede de origem.

---

## 3. Passo a passo manual

Use quando não puder rodar a ferramenta (servidor de cliente, máquina sem Python) ou quando quiser confirmar algo à mão.

> No **PowerShell** do Windows, `curl` é um alias de `Invoke-WebRequest`. Use `curl.exe`.

### Passo 1 — De onde estou saindo?

```bash
curl https://api.ipify.org
```

Esse é o IP que o WAF avalia. Compare:

- **VPN ligada × desligada:** se o IP não muda, a VPN é *split tunnel* e o tráfego para a internet não passa por ela.
- **Sua máquina × máquina do domínio:** são IPs diferentes, e regras de allowlist costumam ser por IP.

Se o alvo usa Cloudflare, o próprio Cloudflare diz qual IP ele enxerga:

```bash
curl https://<host>/cdn-cgi/trace
# ip=...      <- IP que o Cloudflare viu
# colo=GRU    <- PoP (GRU = São Paulo)
# loc=BR
# warp=off
```

### Passo 2 — DNS: para onde o nome aponta?

```bash
nslookup <host>              # resolvedor local (da rede/VPN)
nslookup <host> 8.8.8.8      # resolvedor público
nslookup -type=CNAME <host> 8.8.8.8
```

- **IPs de redes diferentes** entre o resolvedor local e o público indicam **split-horizon DNS**. Na rede interna o nome aponta para um IP privado ou outro destino, e o tráfego pode **nem passar pelo WAF de borda**. Isso explica "funciona na máquina do domínio, falha fora".
- **O CNAME denuncia a CDN:**

| CNAME termina em | Fornecedor |
|---|---|
| `.cdn.cloudflare.net` | Cloudflare |
| `.edgekey.net`, `.edgesuite.net`, `.akamaiedge.net` | Akamai |
| `.cloudfront.net` | AWS CloudFront |
| `.elb.amazonaws.com` | AWS ELB/ALB |
| `.azurefd.net`, `.azureedge.net`, `.t-msedge.net` | Azure Front Door / CDN |
| `.azure-api.net` | Azure API Management |
| `.incapdns.net`, `.impervadns.net` | Imperva (Incapsula) |
| `.fastly.net`, `.fastlylb.net` | Fastly |

> Cloudflare no modo *proxy* não expõe CNAME: o nome resolve direto para IPs do próprio Cloudflare. Nesse caso, siga para o passo 3.

### Passo 3 — ASN do IP: nuvem ou datacenter próprio?

No Windows funciona com `nslookup`, sem instalar nada. Inverta os octetos do IP:

```bash
# IP 104.26.10.137  ->  137.10.26.104
nslookup -type=TXT 137.10.26.104.origin.asn.cymru.com
# "13335 | 104.26.0.0/20 | US | arin | ..."   -> AS13335

nslookup -type=TXT AS13335.asn.cymru.com
# "... | CLOUDFLARENET - Cloudflare, Inc., US"
```

No Linux/macOS: `whois -h whois.cymru.com " -v 104.26.10.137"`.

| ASN | Significado |
|---|---|
| 13335, 209242 | Cloudflare: a borda é do Cloudflare |
| 20940, 16625, 32787 | Akamai (32787 = Prolexic, anti-DDoS) |
| 16509, 14618 | AWS |
| 8075 | Microsoft Azure |
| 19551 | Imperva |
| 54113 | Fastly |
| **Operadora** (ex.: 10429/26599 Telefônica, 7738 Oi, 28573 Claro) | **Datacenter próprio ou colocation.** Não há CDN; a proteção é um appliance on-premise (F5, FortiWeb, NetScaler...) |

Foi assim que se descobriu que `odontoprev.com.br` (IP `187.51.14.88`, **AS10429 Telefônica Brasil**) não usa CDN: o que protege o site é um **F5 no datacenter**.

### Passo 4 — Headers e cookies: a impressão digital

```bash
curl -s -D - -o /dev/null https://<host>/          # Linux/macOS/Git Bash
curl.exe -s -D - -o NUL https://<host>/            # Windows
```

Para uma API, repita **o mesmo método, corpo e headers** da chamada real. Uma regra pode valer só para POST ou só para um caminho.

#### Borda / CDN / WAF em nuvem

| Fornecedor | Headers | Cookies |
|---|---|---|
| **Cloudflare** | `server: cloudflare`, `cf-ray`, `cf-cache-status`, `cf-mitigated` | `__cf_bm`, `cf_clearance`, `_cfuvid`, `__cflb` |
| **Akamai** | `server: AkamaiGHost`, `akamai-grn`, `x-akamai-*` | `ak_bmsc`, `bm_sz`, `_abck` (Bot Manager) |
| **AWS CloudFront** | `x-amz-cf-id`, `x-amz-cf-pop`, `via: ... CloudFront` | — |
| **AWS WAF** | `x-amzn-waf-action` | `aws-waf-token` |
| **Azure Front Door** | `x-azure-ref`, `x-fd-healthprobe` | — |
| **Imperva** | `x-iinfo`, `x-cdn: Imperva` | `visid_incap_*`, `incap_ses_*`, `nlbi_*` |
| **Fastly** | `x-served-by: cache-...`, `x-fastly-request-id` | — |
| **F5 Distributed Cloud** | `server: volt-adc` | — |

#### Appliances (on-premise)

| Fornecedor | Headers | Cookies |
|---|---|---|
| **F5 BIG-IP LTM** (balanceador) | `server: BigIP` (geralmente removido) | `BIGipServer<pool>` |
| **F5 BIG-IP ASM / Advanced WAF** | — | `TS01xxxxxx`, `TSxxxxxxxx_NNN` |
| **F5 BIG-IP AVR** (telemetria) | — | `f5avr..._session_`, `f5_cspm` |
| **F5 BIG-IP APM** (acesso/VPN) | — | `MRHSession`, `LastMRH_Session`, `F5_ST` |
| **Citrix NetScaler / ADC** | `via: NS-CACHE` | `NSC_*`, `citrix_ns_id` |
| **FortiWeb / FortiGate** | `server: FortiWeb` | `FORTIWAFSID`, `cookiesession1` |
| **Barracuda** | — | `barra_counter_session`, `BNI__BARRACUDA_LB_COOKIE` |
| **Azure Application Gateway** | `server: Microsoft-Azure-Application-Gateway/v2` | `ApplicationGatewayAffinity` |

#### Origem

| Servidor | Evidência |
|---|---|
| **IIS / ASP.NET** | `x-powered-by: ASP.NET`, `x-aspnet-version`, `server: Microsoft-IIS/10.0`, cookie `ASP.NET_SessionId` |
| **Kestrel (.NET)** | `server: Kestrel` |
| **nginx / Apache** | `server: nginx` / `server: Apache` (nginx também aparece como proxy reverso) |
| **Node.js** | `x-powered-by: Express` / `Next.js`, cookie `connect.sid` |
| **Nuxt** | cookie `i18n_redirected` (módulo `@nuxtjs/i18n`) |
| **PHP / Java** | `x-powered-by: PHP`, `PHPSESSID` / `JSESSIONID` |

> Quando a borda reescreve o `Server` (ex.: `server: cloudflare`), headers da origem como `x-powered-by: ASP.NET` costumam passar intactos. Foi assim que se viu o IIS atrás do Cloudflare no `obrsos`.

### Passo 5 — Quem respondeu o 403?

Leia o **corpo** da resposta de bloqueio. Cada camada tem uma página própria e um **ID de evento**: é esse ID que permite ao time de infra achar o registro no log.

| Página / sinal | Quem bloqueou | ID para o chamado |
|---|---|---|
| Header `cf-mitigated: challenge`, título `Just a moment...` | **Cloudflare: desafio JS (Managed Challenge)** | `CF-RAY` |
| `Sorry, you have been blocked` / `error code: 1020` | **Cloudflare: regra de firewall** | `CF-RAY` |
| `The requested URL was rejected. Please consult with your administrator. Your support ID is: …` | **F5 BIG-IP ASM / Advanced WAF** (ou NGINX App Protect) | `Support ID` |
| `Access Denied … Reference #18.xxxx` | **Akamai** | `Reference #` |
| `Incapsula incident ID` | **Imperva** | `Incident ID` |
| `Request blocked` + `Generated by cloudfront` | **AWS CloudFront / WAF** | `x-amz-cf-id` |
| 403 com `x-azure-ref` | **Azure Front Door WAF** | `x-azure-ref` |
| `Web Page Blocked!` / `Attack ID` | **FortiWeb / FortiGate** | `Attack ID` |
| `403 - Proibido: o acesso foi negado.` / `HTTP Error 403.x` | **IIS (origem)**: IP Restrictions, autorização ou permissão | horário + URL |
| **Timeout, sem resposta** | Descarte silencioso: firewall, F5 AFM/IP Intelligence, geo-block | horário + seu IP |

**Códigos de erro do Cloudflare (10xx):**

| Código | Significado |
|---|---|
| 1006 / 1007 / 1008 | Seu IP foi banido pelo dono do site |
| 1009 | País/região bloqueado |
| 1010 | Assinatura do navegador/cliente banida |
| 1012 | Acesso negado |
| 1015 | Rate limit |
| 1020 | Bloqueado por regra de firewall (custom rule) |

> **Desafio ≠ bloqueio.** No *Managed Challenge* o Cloudflare pede que o cliente execute JavaScript. Navegador passa; curl, Insomnia, Postman, app mobile e integrações servidor-a-servidor **nunca** passam. Em uma API, isso é quase sempre um erro de configuração: a rota precisa de uma regra *Skip*.

### Passo 6 — Isolar a causa (matriz de testes)

Mude **uma variável por vez** e observe quando o resultado vira:

| Varie | Como | Se o resultado muda, a regra é por... |
|---|---|---|
| **User-Agent** | `--perfis curl navegador insomnia okhttp` | assinatura de cliente / bot |
| **Rede de saída** | sua máquina × máquina do domínio × VPN full tunnel | IP/ASN/allowlist ou reputação do IP |
| **Região** | `gp_check.py --regions BR US DE` | país/geo ou IP de data center |
| **Método / caminho** | GET `/` × POST na rota da API | regra específica de rota |
| **Horário** | repetir minutos depois | regra dinâmica (bot score, rate limit, "Under Attack") ou alguém mudou a regra |

O perfil `navegador` do script troca **apenas** o User-Agent e os headers `Accept`. A impressão digital TLS (JA3/JA4) continua a do Python. Se o Chrome de verdade passa e o perfil `navegador` não, o critério é TLS/JavaScript, e não o User-Agent.

### Passo 7 — Específico do F5 BIG-IP

**Cookie de persistência `BIGipServer<pool>`:**

- O nome revela o **pool** do balanceador.
- Se o valor **começa com `!`**, o cookie está **criptografado**, que é a boa prática (é o caso do `odontoprev.com.br`).
- Se o valor tem o formato `1677787402.20480.0000`, ele **expõe o IP e a porta internos** do servidor. Isso é um achado de segurança a reportar:

```python
import socket, struct
ip_enc, port_enc, _ = "1677787402.20480.0000".split(".")
ip = socket.inet_ntoa(struct.pack("<I", int(ip_enc)))                  # 10.1.1.100
port = struct.unpack("<H", struct.pack(">H", int(port_enc)))[0]        # 80
```

O `waf_detect.py` faz essa decodificação sozinho e avisa quando há vazamento.

**Cookies `TS01xxxxxx`:** são do **ASM / Advanced WAF**, o módulo de WAF do F5. Se eles aparecem, há política de WAF ativa, mesmo que o site nunca tenha bloqueado você.

**Página de bloqueio do ASM:** sempre traz um **Support ID** numérico. Com ele, o time de segurança encontra a violação exata em *Security › Event Logs › Application › Requests*.

**Timeout em vez de 403:** o F5 (com AFM / IP Intelligence) ou o firewall na frente dele pode descartar a conexão sem responder. Esse foi o padrão registrado antes para o `odontoprev.com.br` a partir de IPs de data center (veja a seção ASN do README). Na medição de 14/10/2026, as regiões testadas (BR, US, DE, JP) responderam 200.

---

## 4. Estudo de caso — `obrsos.odontosystem.com.br` (403 no Insomnia, 200 na máquina do domínio)

**Sintoma:** a chamada `POST /OSMarcacaoWS.svc/especialidades-localidade-redes-guia` retornava **403** pelo Insomnia na máquina do desenvolvedor, com ou sem VPN. A mesma curl, na máquina do domínio ODPV, retornava **200**.

**Evidência coletada (13:46 UTC):**

```
HTTP/1.1 403 Forbidden
Server: cloudflare
Cf-Mitigated: challenge
CF-RAY: a4a707f99d93f199-GRU
<title>Just a moment...</title>
```

**Leitura:**

1. `cf-mitigated: challenge` mostra que quem respondeu foi o **Cloudflare**, com um **desafio JavaScript**. A requisição **não chegou ao IIS**.
2. O sufixo `-GRU` no CF-RAY indica que o atendimento foi no PoP de **São Paulo**.
3. O Insomnia não executa JavaScript, então nunca passa no desafio.
4. O IP de saída da máquina era residencial. Como o resultado não mudava com a VPN, o mais provável é que ela seja *split tunnel* e não carregue esse tráfego. Para confirmar, compare `curl https://api.ipify.org` com a VPN ligada e desligada.

**O que mais se descobriu medindo:**

| Teste | Resultado |
|---|---|
| Pilha | Cloudflare (AS13335) → IIS / ASP.NET (`x-powered-by: ASP.NET`) |
| GlobalPing, GET `/` a partir de BR, US e DE (IPs de data center) | **403 Managed Challenge nas 3 regiões** |
| Máquina do desenvolvedor, GET `/` com UA `curl` × navegador | Variou: desafio em um horário, 200 em outro |
| A mesma chamada POST, **mesmo IP**, ~1h30 depois | **200** |

**Conclusão:** o Cloudflare decide desafiar com base na **reputação/tipo do IP** (data center é sempre desafiado) e em sinais de bot (User-Agent), e a decisão **muda ao longo do tempo**. Há duas explicações possíveis: *Bot Fight Mode* / *Security Level* dinâmico, ou uma regra alterada por alguém nesse intervalo. A máquina do domínio provavelmente sai por um IP com reputação boa ou liberado em regra.

**Encaminhamento recomendado ao time que administra o Cloudflare:**

- Criar uma regra WAF **Skip** (pular Managed Challenge / Bot Fight Mode) para `obrsos.odontosystem.com.br/OSMarcacaoWS.svc/*`. Rotas de API não devem receber desafio JS, porque o app mobile também é um cliente sem navegador.
- Se for preciso restringir quem chama a API, use um **token em header**, um **Cloudflare Access Service Token** ou **mTLS** no lugar do desafio.
- Anexe ao chamado: CF-RAY, horário (UTC), método e rota, e o IP de saída (`/cdn-cgi/trace`).

---

## 5. Checklist para abrir chamado com infra/segurança

- [ ] **Quem bloqueou** (camada + fornecedor) e a evidência (header/página)
- [ ] **ID do evento:** CF-RAY / Support ID / Reference # / Incident ID / x-azure-ref / x-amz-cf-id
- [ ] **Horário exato** (UTC) da tentativa
- [ ] **Método, URL e headers** da requisição (sem tokens/senhas)
- [ ] **IP de saída** usado (e o IP que funciona, se houver comparação)
- [ ] **Resultado da matriz de testes:** o que muda o comportamento (UA, rede, região, rota)
- [ ] **Pedido objetivo:** "regra Skip para a rota X", "allowlist do IP Y", "liberar país Z"...

O JSON gerado com `python waf_detect.py ... --json chamado.json` (salvo em `output/`) já contém tudo isso, menos o pedido.

---

## 6. Limitações

- **Fingerprint passivo pode ser escondido.** Headers e cookies podem ser removidos ou renomeados. Sem assinatura, use o ASN do IP e a página de erro.
- **Uma camada pode esconder a seguinte.** O Cloudflare na frente de um F5 mostra os cookies do F5 apenas quando a requisição chega até ele. Se a borda bloqueia, as camadas internas ficam invisíveis.
- **O GlobalPing só faz GET/HEAD** e o corpo vem truncado em 10 KB. Para POST com corpo, use o `waf_detect.py` local.
- **Regras dinâmicas:** bot score, rate limit e reputação de IP mudam com o tempo. Sempre registre horário e ID do evento.
- **TLS fingerprint:** trocar o User-Agent não imita um navegador real.
