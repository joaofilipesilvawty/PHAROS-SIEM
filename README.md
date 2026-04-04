# SIEM — Sistema de Informação e Eventos de Segurança

Aplicação web e API para recolha de logs de segurança, alertas, métricas e dashboard de administração, com persistência em **Oracle** via **JRuby + OJDBC**.

## Funcionalidades

- Dashboard web (login, alertas, logs, métricas, relatórios, definições) em Sinatra/ERB
- API REST para logs, alertas e métricas; validação opcional via `APISecurity` (JWT, API key de ingestão)
- Modelos Sequel: `admins`, `sessions`, `security_logs`, `alerts`, `metrics`
- Integração opcional VirusTotal (chave em `.env`)
- **Redis** opcional (rate limit / chaves)
- Variáveis **Elasticsearch** no `.env` para configuração futura (a app ainda não envia dados ao cluster)

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
│   └── services/             # Análise, threat intel, API security, etc.
├── install.sh                # Deploy Linux + systemd (não macOS)
```

## Requisitos

| Componente | Notas |
|------------|--------|
| **JRuby** | Versão em `.ruby-version` (ex.: 9.4.5.0) |
| **JDK** | 11 ou superior (JRuby corre na JVM) |
| **Oracle** | 12c+ com service name acessível na rede |
| **OJDBC** | Ficheiro `lib/ojdbc8-*.jar` no repositório (ajusta a versão ao teu servidor Oracle se precisares) |
| **Redis** | Opcional |

Não é necessário Oracle Instant Client nem `ruby-oci8` no sistema: a ligação é feita só por JDBC no JRuby.

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

## Executar

```bash
bundle exec ruby server.rb
```

Por omissão: `http://127.0.0.1:4567` — login em `/login`, dashboard em `/dashboard`.

### Linux (systemd)

Para instalação em servidor Linux, vê `install.sh` (requer root; no macOS o script apenas imprime instruções).

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

## Resolução de problemas

- **`Errno::EADDRINUSE` na porta 4567** — Já há outro processo (ex.: instância anterior do servidor). Identifica com `lsof -nP -iTCP:4567 -sTCP:LISTEN` e termina o PID, ou altera `PORT` no `.env`.
- **`Missing migration version: 1`** — Os ficheiros em `settings/db/migrations/` têm de começar em `001_` e ser consecutivos.
- **`ORA-00942` tabela não existe** — Corre `bundle exec rake db:migrate` com credenciais Oracle corretas.

## Desenvolvimento

Ferramentas em grupo `:development` do `Gemfile`: Rake, RuboCop, Pry. Não há suíte RSpec incluída neste repositório; podes adicionar testes à medida.

## Contribuição

1. Fork do repositório  
2. Branch para a funcionalidade (`git checkout -b feature/nome`)  
3. Commit com mensagens claras  
4. Push e Pull Request  
