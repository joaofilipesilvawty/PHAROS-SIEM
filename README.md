# SIEM - Sistema de Monitoramento de Segurança para Fintech

Este é um Sistema de Informação e Eventos de Segurança (SIEM) desenvolvido para monitorar e analisar eventos de segurança em uma fintech.

## Funcionalidades Principais

- Coleta e processamento de logs de segurança
- Análise de padrões suspeitos
- Geração de alertas em tempo real
- Monitoramento de transações
- Dashboard de métricas
- Integração com Oracle Database

## Estrutura do Projeto

```
.
├── server.rb              # Servidor principal
├── settings/          # Configurações e modelos
│   ├── config/       # Configurações do sistema
│   ├── db/          # Esquema e migrações do banco de dados
│   ├── endpoints/   # Endpoints da API
│   ├── middleware/  # Middleware da aplicação
│   ├── models/      # Modelos do banco de dados
│   └── services/    # Serviços da aplicação
├── spec/                # Testes
├── log/                 # Logs da aplicação
└── tmp/                 # Arquivos temporários
```

## Requisitos

- **JRuby** (versão em `.ruby-version`, ex. 9.4.5.0) e **JDK** 11+
- **Oracle Database** 12c ou superior (acessível por rede)
- **OJDBC** no repositório: `lib/ojdbc8-19.26.0.0.jar` (ou substitui por versão compatível com o teu Oracle)

Não é necessário Oracle Instant Client nem `ruby-oci8` no sistema — a ligação é feita por JDBC dentro do JRuby.

## Configuração

1. Clone o repositório
2. Active o JRuby (ex. rbenv):

   ```bash
   rbenv install "$(cat .ruby-version)"
   rbenv local "$(cat .ruby-version)"
   ```

3. Instale as dependências:

   ```bash
   bundle install
   ```

4. Variáveis de ambiente:

   ```bash
   cp .env.example .env
   # Edite .env: ORACLE_HOST, ORACLE_PORT, ORACLE_SERVICE_NAME, ORACLE_USERNAME, ORACLE_PASSWORD
   ```

5. Migrações:

   ```bash
   bundle exec rake db:migrate
   ```

## Executando o Projeto

```bash
bundle exec ruby server.rb
```

## Endpoints da API

- `GET /health` - Verifica a saúde do sistema
- `POST /logs` - Recebe logs de segurança
- `GET /alerts` - Consulta alertas
- `GET /metrics` - Consulta métricas

## Desenvolvimento

Para executar os testes:

```bash
bundle exec rspec
```

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request
