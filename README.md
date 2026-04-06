# PHAROS — SIEM (Sistema de Informação e Eventos de Segurança)

<!-- Template de vitrine: substitui os placeholders entre [ ] conforme quiseres partilhar no GitHub ou no LinkedIn. -->

<div align="center">

**PHAROS** é uma plataforma web e API para recolha de logs de segurança, correlação de alertas, métricas e painel de administração, com persistência em **Oracle** e stack **JRuby + JDBC**.

*Nome inspirado no farol de **Pharos** — luz e referência para navegar em meio a ruído e eventos.*

</div>

<div align="center">

[Badges opcionais — exemplo:]
<!-- [![JRuby](https://img.shields.io/badge/JRuby-9.4+-red?logo=ruby)](https://www.jruby.org/) [![Oracle](https://img.shields.io/badge/Oracle-12c%2B-F80000?logo=oracle)](https://www.oracle.com/database/) [![Sinatra](https://img.shields.io/badge/Sinatra-Web-000000?logo=sinatra)](https://sinatrarb.com/) -->

</div>

---

## Visão geral (para portfólio)

**PHAROS** é um **SIEM orientado a operações de segurança**: centraliza ingestão de eventos, expõe uma **API REST** com autenticação configurável (JWT, chave de ingestão), oferece **dashboard** para analistas e camada de serviços para **análise de ameaças**, integração opcional com **VirusTotal** e preparação para evolução com **Elasticsearch** e **Redis**.

**Objetivo profissional:** demonstrar competências em **segurança da informação**, **backend Ruby/JRuby**, **bases de dados empresariais (Oracle)**, **APIs REST**, **modelagem de dados (Sequel)** e **operacionalização** (health checks, deploy Linux/systemd).

| Onde partilhar | Sugestão |
|----------------|----------|
| **GitHub** | Usa este README como página principal do repo; adiciona tópicos (`pharos`, `siem`, `jruby`, `oracle`, `sinatra`, `cybersecurity`). |
| **LinkedIn** | Na secção *Projetos* ou num post: copia o bloco [Texto curto para LinkedIn](#texto-curto-para-linkedin) abaixo e adapta. |

---

## O que o sistema faz

- **Dashboard web** (login, alertas, logs, métricas, relatórios, definições) com **Sinatra** e views **ERB**.
- **API REST** para logs, alertas e métricas, com validação opcional via `APISecurity` (**JWT**, **API key** de ingestão).
- **Modelos Sequel**: `admins`, `sessions`, `security_logs`, `alerts`, `metrics`.
- **Threat intelligence** opcional via **VirusTotal** (chave em `.env`).
- **Redis** opcional (rate limit / chaves).
- Variáveis **Elasticsearch** no `.env` para configuração futura (a aplicação ainda não envia dados ao cluster).

---

## Stack técnica

| Área | Tecnologia |
|------|------------|
| Runtime | **JRuby** (JVM) |
| Base de dados | **Oracle 12c+** via **OJDBC** (`lib/ojdbc8-*.jar`) — sem Instant Client no host |
| ORM / migrações | **Sequel** + **Rake** (`db:migrate`) |
| Web | **Sinatra**, **Puma**, **Rack::CORS** |
| Segurança | **bcrypt**, **JWT**, camada `APISecurity` |
| Observabilidade / extras | **Prometheus client**, **Logstash logger**, **syslog_protocol** |
| Cache / filas | **Redis** (opcional) |

---

## Arquitetura (resumo)

```
Clientes / integrações
        │
        ▼
┌───────────────────┐     ┌─────────────┐     ┌──────────────┐
│  Sinatra (HTTP)   │────▶│  Serviços   │────▶│ Oracle JDBC  │
│  Dashboard + API  │     │  análise,   │     │ (Sequel)     │
└───────────────────┘     │  threat,    │     └──────────────┘
        │                 │  MDR, etc.  │
        │                 └──────┬───────┘
        │                        │
        ▼                        ▼
   Redis (opc.)            VirusTotal (opc.)
```

---

## Estrutura do projeto

```
.
├── server.rb                 # App Sinatra + ligação Oracle (JDBC)
├── Rakefile                  # db:migrate
├── lib/ojdbc8-19.26.0.0.jar  # Driver Oracle (JDBC)
├── dashboard/public/         # Views ERB, assets, layout
├── settings/
│   ├── config/               # Inicializadores
│   ├── db/migrations/        # Migrações Sequel (001_, 002_, … consecutivos)
│   ├── endpoints/            # Handlers da API
│   ├── middleware/
│   ├── models/
│   └── services/             # Análise, threat intel, API security, MDR, etc.
├── install.sh                # Deploy Linux + systemd (não macOS)
```

---

## Requisitos

| Componente | Notas |
|------------|--------|
| **JRuby** | Versão em `.ruby-version` (ex.: 9.4.5.0) |
| **JDK** | 11 ou superior (JRuby corre na JVM) |
| **Oracle** | 12c+ com service name acessível na rede |
| **OJDBC** | Ficheiro `lib/ojdbc8-*.jar` no repositório (ajusta a versão ao teu servidor Oracle se precisares) |
| **Redis** | Opcional |

Não é necessário Oracle Instant Client nem `ruby-oci8` no sistema: a ligação é feita só por JDBC no JRuby.

---

## Configuração rápida

1. **JRuby** (ex.: rbenv):

   ```bash
   rbenv install "$(cat .ruby-version)"
   rbenv local "$(cat .ruby-version)"
   ```

2. **Dependências:**

   ```bash
   bundle install
   ```

3. **Ambiente:**

   ```bash
   cp .env.example .env
   ```

   Preenche no mínimo `ORACLE_HOST`, `ORACLE_PORT`, `ORACLE_SERVICE_NAME`, `ORACLE_USERNAME`, `ORACLE_PASSWORD`. Opcional: `REDIS_*`, `SESSION_SECRET`, `ADMIN_PASSWORD` (bootstrap do primeiro admin), `INGEST_API_KEY`, `API_JWT_SECRET`, VirusTotal, bloco Elasticsearch.

4. **Migrações** (ficheiros numerados **001, 002, 003…** sem saltos — requisito do Sequel):

   ```bash
   bundle exec rake db:migrate
   ```

   O `Rakefile` carrega `server.rb`; na **primeira** corrida podes ver `[SIEM] Bootstrap admin ignorado` se as tabelas ainda não existiam — é normal **antes** das migrações terminarem. Depois das migrações, ao arrancar o servidor o bootstrap do `admin` corre se a tabela `admins` estiver vazia (ou define `ADMIN_PASSWORD` no `.env`).

---

## Executar

```bash
bundle exec ruby server.rb
```

Por omissão: `http://127.0.0.1:4567` — login em `/login`, dashboard em `/dashboard`.

### Linux (systemd)

Para instalação em servidor Linux, vê `install.sh` (requer root; no macOS o script apenas imprime instruções).

---

## API e rotas úteis

| Método | Caminho | Descrição |
|--------|---------|-----------|
| `GET` | `/health` | Estado da ligação à base de dados |
| `GET` | `/login` | Página de login |
| `POST` | `/auth/login` | Login de sessão (form) |
| `GET` | `/dashboard` | Dashboard (sessão obrigatória) |
| `POST` | `/logs` | Ingestão de logs (validação conforme `APISecurity`) |
| `GET` | `/logs` | Listagem de logs |
| `GET`/`POST` | `/alerts` | Consulta / criação de alertas |
| `GET` | `/metrics` | Métricas |
| `POST` | `/admin/login` | Login JSON (token de sessão em `sessions`) |
| `POST` | `/api/virustotal/analyze-threat` | Análise com ficheiro (ThreatIntelligence) |

Rotas sob `/dashboard/*` e parte da API podem exigir autenticação; consulta `settings/services/api_security.rb` e o filtro `before` em `server.rb`.

---

## Texto curto para LinkedIn

*Copia e adapta (1º pessoa, 2–4 linhas):*

> **PHAROS** — SIEM em **JRuby + Oracle**: API REST para ingestão de logs e alertas, dashboard para operações de segurança, autenticação por JWT/API key e integração opcional com **VirusTotal** e **Redis**. Modelagem com **Sequel**, serviços de análise e preparação para **Elasticsearch**.  
> Repositório: [colar URL do GitHub]

---

## Checklist de vitrine (GitHub)

- [ ] Adicionar **screenshot** do dashboard em `docs/` ou na secção acima (substituir comentário HTML por `![Dashboard](docs/screenshot.png)`).
- [ ] Preencher **URL do repositório** no texto do LinkedIn.
- [ ] (Opcional) Ativar os **badges** no topo, descomentando o bloco HTML.
- [ ] (Opcional) Indicar **demo** ou vídeo: [link ou N/A].

---

## Resolução de problemas

- **`Errno::EADDRINUSE` na porta 4567** — Já há outro processo (ex.: instância anterior do servidor). Identifica com `lsof -nP -iTCP:4567 -sTCP:LISTEN` e termina o PID, ou altera `PORT` no `.env`.
- **`Missing migration version: 1`** — Os ficheiros em `settings/db/migrations/` têm de começar em `001_` e ser consecutivos.
- **`ORA-00942` tabela não existe** — Corre `bundle exec rake db:migrate` com credenciais Oracle corretas.

---

## Desenvolvimento

Ferramentas em grupo `:development` do `Gemfile`: Rake, RuboCop, Pry. Não há suíte RSpec incluída neste repositório; podes adicionar testes à medida.

Antes de commit, podes seguir `01-PRE-COMMIT-COMMANDS.md`.

---

## Contribuição

1. Fork do repositório  
2. Branch para a funcionalidade (`git checkout -b feature/nome`)  
3. Commit com mensagens claras  
4. Push e Pull Request  

---

## Licença e autor

**PHAROS** está licenciado sob a [**GNU General Public License v3.0**](https://www.gnu.org/licenses/gpl-3.0.html) (GPLv3). O texto completo está no ficheiro [`LICENSE`](LICENSE) na raiz do repositório.

Em termos gerais, podes usar, estudar, modificar e redistribuir o código; se redistribuíres versões modificadas, essas alterações devem continuar disponíveis sob a mesma licença. Para obrigações e excepções exactas, lê o `LICENSE`.

**Autor:** João Filipe Silva — [GitHub](https://github.com/joaofilipesilvawty) · [LinkedIn](https://www.linkedin.com/in/joaofilipesilvawty/)
