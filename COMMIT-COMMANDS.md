# 0. Fazer Migrate
bundle exec rake db:migrate

# 1. Adicionar todos os arquivos modificados
git add -A

# 2.a. Commit com mensagem
git commit -m "mensagem"

# 2.b. Commit ignorando hooks (quando necessário)
git commit --no-verify -m "mensagem"

# 3. Push para o remoto
git push
```
