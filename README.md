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

- Ruby 3.0+
- Oracle Database 12c ou superior
- Oracle Instant Client
- Ruby-OCI8

## Configuração

1. Clone o repositório
2. Instale as dependências:

   ```bash
   bundle install
   ```

3. Configure as variáveis de ambiente:

   ```bash
   cp .env.example .env
   # Edite o arquivo .env com suas configurações do Oracle
   ```

4. Configure o Oracle Instant Client:
   - Baixe e instale o Oracle Instant Client
   - Configure as variáveis de ambiente ORACLE_HOME e LD_LIBRARY_PATH
   - Instale o ruby-oci8

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
