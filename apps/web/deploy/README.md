# Deploy — fracta.pro

Padrão da frota: **build no GitHub Actions → imagem no GHCR → VPS só faz pull + restart**.
A VPS (76.13.170.79, `ssh hostinger`) **nunca** builda Docker.

## 1. Imagem (automático)
`.github/workflows/deploy-web.yml` builda `apps/web/Dockerfile` e publica
`ghcr.io/andersongadelhaadv-cmyk/fracta-web:latest` a cada push em `master` que toque
`apps/web/**` ou `packages/**`. Depois faz SSH na VPS → `docker compose pull && up -d` + healthcheck.

> **Uma vez:** deixar o package GHCR `fracta-web` **público** (Settings → Packages) para a VPS
> puxar sem login. Alternativa: `docker login ghcr.io` na VPS com um token read:packages.

## 2. VPS — compose + volume (setup único)
```bash
ssh hostinger
mkdir -p /opt/apps/fracta-web/data
# copiar apps/web/deploy/docker-compose.yml para /opt/apps/fracta-web/docker-compose.yml
cd /opt/apps/fracta-web && docker compose pull && docker compose up -d
curl -fsS http://127.0.0.1:3850 >/dev/null && echo OK   # porta 3850 (loopback)
```
Porta **3850** escolhida fora das faixas em uso (ver memory infra-vps-deploy).

## 3. nginx — vhost + TLS + endurecer o default
```bash
# vhost dedicado
cp apps/web/deploy/nginx-fracta.pro.conf /etc/nginx/sites-available/fracta.pro
ln -s /etc/nginx/sites-available/fracta.pro /etc/nginx/sites-enabled/fracta.pro
nginx -t && systemctl reload nginx
# cert Let's Encrypt (adiciona o bloco :443 + redirect)
certbot --nginx -d fracta.pro -d www.fracta.pro
```

### Endurecer o `default_server` → 444 (corrige a causa-raiz)
Hoje `fracta.pro` caía no `default_server` e servia a home do ADVOCUS (erro de CORS).
Achar o catch-all (`nginx -T | grep -n default_server`) e, **só nesse bloco** (sem tocar nos
`server_name` legítimos dos outros apps), retornar 444 para host desconhecido em :80 e :443
(o :443 default precisa de um cert snakeoil para não vazar outro vhost):
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    return 444;
}
```
`nginx -t` e backup de cada arquivo (`*.bak.fractapro.$(date +%s)`) antes de cada `reload`.

## 4. Verificação
```bash
curl -I https://fracta.pro                      # 200, home do Fracta (não ADVOCUS), TLS válido
curl -sI http://76.13.170.79 -H 'Host: lixo.x'  # conexão fechada (444)
```
