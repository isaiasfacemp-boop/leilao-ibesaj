# Leilão IBESAJ — Sistema de Controle de Arremate

Sistema web para gerenciar o leilão beneficente: cadastro de lotes, arremates ao vivo,
login com usuário e senha, código de barras, etiquetas e cartões para impressão.

## Estrutura
- `worker.js` — backend (Cloudflare Worker): API, login, usuários, lotes
- `wrangler.toml` — configuração de deploy (já aponta para o banco D1 `leilao-ibesaj-db`)
- `public/index.html` — frontend (única página, sem build necessário)

## Deploy
```bash
npm install -g wrangler   # se ainda não tiver
wrangler login             # autoriza sua conta Cloudflare
wrangler deploy             # publica o sistema
```

O link final aparece no terminal ao fim do deploy, algo como:
`https://leilao-ibesaj-api.SEU-SUBDOMINIO.workers.dev`

## Funcionalidades
- Login obrigatório; o primeiro acesso cria o usuário administrador
- Administradores podem criar outros usuários pela aba "Usuários"
- Sincronização entre todos os aparelhos a cada poucos segundos
- Leitura de código de barras pela câmera do celular
- Dashboard com gráficos, etiquetas e cartões de lance para impressão
- Apenas administradores podem excluir lotes ou desfazer arremates
