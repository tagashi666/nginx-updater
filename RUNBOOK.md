# Nginx Upgrade Runbook — CVE-2026-42945 (NGINX Rift)

**Цель:** проапгрейдить nginx до **1.30.1** (stable) или **1.31.0** (mainline) на всех серверах. Без даунтайма и без сюрпризов.

**Почему нужен полный restart, а не reload:** фикс затрагивает heap layout воркеров. После `reload` старый мастер может оставить старые воркеры до завершения in-flight запросов — этого недостаточно.

---

## 0. Pre-flight

- Root/sudo на каждом сервере.
- Знание адресов и имён всех сервисов, которые висят за nginx (для smoke-теста).
- Окно времени с возможностью полного restart.
- Если используешь Cloudflare или другой upstream — там тоже есть свой edge nginx, но это не твоя забота; обновляешь только то, что у тебя.

---

## 1. Inventory: что запущено на сервере

Запускать на каждом сервере. Вывод сохраняй.

### 1.1 Системный nginx

```bash
# Версия (если установлен)
nginx -v 2>&1 || echo "no system nginx"

# Статус сервиса
systemctl status nginx --no-pager 2>/dev/null || service nginx status 2>/dev/null

# Путь бинарника и откуда поставлен
which nginx
dpkg -S "$(which nginx)" 2>/dev/null || rpm -qf "$(which nginx)" 2>/dev/null

# Что слушает на 80/443/8443
ss -tlnp | grep -E ':(80|443|8443) '
```

### 1.2 Docker

```bash
# Контейнеры с nginx (по имени образа)
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' | grep -iE 'nginx|openresty'

# Версия внутри каждого контейнера, где есть бинарь nginx
for c in $(docker ps --format '{{.Names}}'); do
  v=$(docker exec "$c" nginx -v 2>&1 || true)
  [ -n "$v" ] && echo "$c → $v"
done

# Локальные образы (чтобы видеть, что вообще лежит)
docker images | grep -iE 'nginx|openresty'
```

### 1.3 Compose-стеки и спрятанный nginx

```bash
# Compose проекты (новый CLI)
docker compose ls 2>/dev/null

# Все compose-файлы на машине
find / -xdev -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' 2>/dev/null | head -20
```

> Не забудь про nginx, который мог уехать в кастомные образы (своя сборка с nginx внутри). Их найти можно так: `docker images -q | xargs -I{} docker run --rm --entrypoint sh {} -c 'nginx -v 2>&1' 2>/dev/null`. Долго, но честно.

---

## 2. Audit: есть ли реально уязвимый паттерн?

Патч ставим в любом случае. Но полезно знать, был ли в конкретном конфиге путь к RCE.

**Уязвимый паттерн:** директива `rewrite` с unnamed capture (`$1`, `$2`, …) и `?` в replacement, за которой стоит `rewrite`/`if`/`set`.

```bash
# Системный nginx
grep -rnE 'rewrite[[:space:]]+.*\$[0-9].*\?' /etc/nginx/ 2>/dev/null

# Все контейнеры
for c in $(docker ps --format '{{.Names}}'); do
  echo "=== $c ==="
  docker exec "$c" sh -c 'grep -rnE "rewrite[[:space:]]+.*\\\$[0-9].*\?" /etc/nginx/ 2>/dev/null'
done
```

Что-то нашлось — это **кандидат**, не приговор. Смотри глазами, есть ли рядом `rewrite`/`if`/`set`.

---

## 3. Backup

```bash
STAMP=$(date +%F-%H%M)

# Конфиги системного nginx
tar czf /root/nginx-conf-${STAMP}.tgz /etc/nginx/ 2>/dev/null

# Зафиксировать текущие версии пакетов (для roll-back)
dpkg -l 'nginx*' > /root/nginx-pkgs-${STAMP}.txt 2>/dev/null \
  || rpm -qa 'nginx*' > /root/nginx-pkgs-${STAMP}.txt 2>/dev/null

# Запомнить теги докер-образов и команды запуска контейнеров
docker ps --format '{{.Names}}\t{{.Image}}' | grep -iE 'nginx|openresty' \
  > /root/nginx-images-${STAMP}.txt
for c in $(docker ps --format '{{.Names}}' | grep -iE 'nginx|openresty'); do
  docker inspect "$c" > /root/nginx-inspect-${c}-${STAMP}.json
done
```

---

## 4. Upgrade

### 4A. Системный nginx — Debian/Ubuntu, репо nginx.org (рекомендуемый путь)

Проверь, что репо подключён:
```bash
grep -rh 'nginx.org' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
```

Если **подключён**:
```bash
apt update
apt-cache policy nginx | head -20         # увидеть Candidate
apt install -y nginx
```

Если **не подключён**, добавь:
```bash
curl -fsSL https://nginx.org/keys/nginx_signing.key \
  | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

# Stable (1.30.1) — для прода обычно лучше stable:
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/$(. /etc/os-release; echo $ID)/ \
$(. /etc/os-release; echo $VERSION_CODENAME) nginx" \
  > /etc/apt/sources.list.d/nginx.list

# Для mainline (1.31.0) — замени /packages/ на /packages/mainline/

apt update && apt install -y nginx
```

### 4B. Системный nginx — репо дистрибутива

Дистрибутивные репозитории часто отстают, и 1.30.1 туда сразу не доедет:
```bash
apt update
apt-cache policy nginx
```
Если `Candidate` < 1.30.1 — переключайся на 4A.

### 4C. RHEL / Alma / Rocky / Oracle

```bash
cat > /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF

dnf clean all
dnf install -y nginx
```

### 4D. Docker — обычный `docker run`-контейнер

Сначала вытащи параметры запуска контейнера, чтобы воссоздать его 1-в-1:
```bash
CONTAINER=web      # подставь имя своего контейнера

docker inspect "$CONTAINER" | jq '.[0] | {
  Image, Cmd: .Config.Cmd, Entrypoint: .Config.Entrypoint,
  Env: .Config.Env, Mounts, Ports: .HostConfig.PortBindings,
  Restart: .HostConfig.RestartPolicy, Net: .HostConfig.NetworkMode
}'
```

Апгрейд через rename-strategy (быстрый rollback):
```bash
NEW_TAG=nginx:1.31.0          # или nginx:1.30.1 / nginx:stable / nginx:mainline

docker pull "$NEW_TAG"
docker stop "$CONTAINER"
docker rename "$CONTAINER" "${CONTAINER}-old"

# Повторяешь оригинальные параметры из inspect выше:
docker run -d --name "$CONTAINER" \
  --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v /etc/nginx:/etc/nginx:ro \
  -v /var/log/nginx:/var/log/nginx \
  "$NEW_TAG"

# Проверка
docker logs --tail 50 "$CONTAINER"
docker exec "$CONTAINER" nginx -v
docker exec "$CONTAINER" nginx -t

# Если всё ок:
docker rm "${CONTAINER}-old"
```

### 4E. Docker Compose

```bash
cd /path/to/compose/project

# Если в compose.yml зафиксирован тег — обнови (посмотри diff перед коммитом!)
sed -i.bak 's|\(nginx:\)[0-9][0-9.]*|\11.31.0|g' docker-compose.yml
diff docker-compose.yml.bak docker-compose.yml

docker compose pull nginx
docker compose up -d nginx
docker compose logs --tail 50 nginx
```

Если использовался `nginx:latest`, `nginx:mainline` или `nginx:stable` — просто:
```bash
docker compose pull nginx && docker compose up -d nginx
```

### 4F. Кастомная сборка из исходников

```bash
# Запомнить флаги текущей сборки
nginx -V 2>&1 | tee /root/nginx-build-flags-$(date +%F).txt

cd /usr/local/src
wget https://nginx.org/download/nginx-1.31.0.tar.gz
echo "<sha256 с nginx.org> nginx-1.31.0.tar.gz" | sha256sum -c -    # сверить хэш
tar xzf nginx-1.31.0.tar.gz && cd nginx-1.31.0
./configure <те же --with-* флаги, что были в nginx -V>
make -j"$(nproc)"
make install
```

> Для бинарного апгрейда без даунтайма (USR2/WINCH/QUIT) — нет, здесь не подходит: тебе нужен полный рестарт воркеров, см. п. 6.

---

## 5. Verify

```bash
# 5.1 Версия — должна быть ≥ 1.30.1 (stable) или ≥ 1.31.0 (mainline)
nginx -v
# или для контейнера:
docker exec <c> nginx -v

# 5.2 Конфиг валиден
nginx -t
docker exec <c> nginx -t

# 5.3 Сервис/контейнер живой
systemctl status nginx --no-pager
docker ps | grep -iE 'nginx|openresty'

# 5.4 Слушает ожидаемые порты
ss -tlnp | grep -E ':(80|443|8443) '

# 5.5 Smoke test — реальные ответы
curl -skI https://sellerdashboard.ru/      | head -5
curl -skI https://sync.sellerdashboard.ru/ | head -5

# 5.6 Логи на ошибки в первые минуты после рестарта
tail -f /var/log/nginx/error.log
# или docker logs -f <c>
```

---

## 6. Restart (полный, не reload)

```bash
# Системный
systemctl restart nginx

# Docker
docker restart <container>
```

Повтори п. 5 после рестарта.

---

## 7. Rollback

### Debian/Ubuntu
```bash
# Достать предыдущую версию из снимка
cat /root/nginx-pkgs-<STAMP>.txt | grep '^ii  nginx '
apt install -y --allow-downgrades nginx=<старая_версия>
systemctl restart nginx

# Если совсем плохо — конфиг из tarball
tar xzf /root/nginx-conf-<STAMP>.tgz -C /
systemctl restart nginx
```

### Docker
```bash
docker stop <container>
docker rm <container>
docker rename <container>-old <container>
docker start <container>
```

---

## 8. Чеклист (на каждый сервер)

- [ ] Inventory собран (системный + все docker-инстансы)
- [ ] Audit на уязвимый rewrite-паттерн пройден
- [ ] Backup конфигов + список пакетов + inspect контейнеров
- [ ] Upgrade до ≥ 1.30.1 / 1.31.0 выполнен
- [ ] `nginx -t` без ошибок
- [ ] **Полный restart** (не reload)
- [ ] `nginx -v` показывает новую версию
- [ ] Все ожидаемые порты слушаются
- [ ] `curl` к публичным хостам возвращает ожидаемые ответы
- [ ] `error.log` чистый первые 5 минут

---

## 9. Замечание про Reality-сервер

На сервере с Xray + Remnawave nginx сидит на `127.0.0.1:8443` как fallback. При апгрейде:

- Контракт `listen 127.0.0.1:8443` не меняй — Reality форвардит именно туда.
- TLS 1.3 / X25519 / OCSP stapling — это конфиг, не пакет, бэкап его уже снят на шаге 3.
- После рестарта обязательно подтверди:
  ```bash
  ss -tlnp | grep '127.0.0.1:8443'
  ```
- Пока Remnawave node выключен, на 443 фактически торчит nginx напрямую → этот сервер патчишь **первым**.
- На основном проде (sellerdashboard.ru) — апгрейд тоже идёт через restart; убедись, что acme.sh-хук рендера сертификатов не запустится в момент рестарта (если он у тебя по cron — посмотри расписание).

---

## 10. Quick-cheatsheet (одной портянкой)

Стандартный сервер на Debian/Ubuntu с системным nginx из nginx.org репо:
```bash
apt update && apt install -y nginx \
  && nginx -v && nginx -t \
  && systemctl restart nginx \
  && ss -tlnp | grep -E ':(80|443) ' \
  && curl -skI https://$(hostname -f)/ | head -3
```

Стандартный сервер на Docker Compose с тегом в yml:
```bash
sed -i.bak 's|\(nginx:\)[0-9][0-9.]*|\11.31.0|g' docker-compose.yml \
  && docker compose pull nginx \
  && docker compose up -d nginx \
  && docker compose exec nginx nginx -v \
  && docker compose exec nginx nginx -t \
  && docker compose logs --tail 30 nginx
```
