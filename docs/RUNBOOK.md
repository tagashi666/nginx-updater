# Runbook — nginx security upgrade

Ручная процедура и разбор нештатных ситуаций. Скрипт `nginx-upgrade.sh` делает всё описанное ниже сам; этот документ нужен, когда надо понять, **что именно** он сделал, проверить его руками или разобрать случай, который он честно пометил как ручной.

Актуальный порог безопасности: **stable ≥ 1.30.4**, **mainline ≥ 1.31.3**.
Он смещается с каждым новым адвизори — сверяйся с [nginx.org/en/security_advisories.html](https://nginx.org/en/security_advisories.html), а не с этим файлом.

---

## 0. Pre-flight

```bash
uname -a; cat /etc/os-release
df -h /var /etc          # места под бэкап хватает?
systemctl is-active nginx
```

Окно обслуживания: рестарт nginx — это **разрыв всех соединений**, включая websocket и long-poll. `reload` в этом случае недостаточно (фикс задевает разметку кучи воркеров), нужен полный `restart`.

---

## 1. Inventory

### 1.1 Системный nginx

```bash
nginx -v 2>&1                       # версия
nginx -V 2>&1                       # флаги сборки — понадобятся при откате
command -v nginx; readlink -f "$(command -v nginx)"
dpkg -S "$(command -v nginx)" 2>/dev/null || rpm -qf "$(command -v nginx)" 2>/dev/null
ss -tlnp | grep -E 'nginx'
```

Откуда поставлен — критично для выбора пути обновления:

```bash
grep -rn '^[^#]*nginx\.org' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
# пусто → пакет дистрибутива; есть → уже на апстриме
```

### 1.2 Проверка бэкпорта (шаг, который чаще всего пропускают)

**Номер версии сам по себе ничего не значит.** Debian/Ubuntu/RHEL бэкпортят фиксы, не поднимая версию. `nginx 1.24.0` на Ubuntu 24.04 может быть полностью пропатчен.

```bash
zcat /usr/share/doc/nginx-common/changelog.Debian.gz | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u
# RHEL:
rpm -q --changelog nginx | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u
# Alpine:
apk info -a nginx 2>/dev/null | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u
```

Если нужный CVE в списке — **сервер уже защищён, ничего делать не нужно**. Миграция на nginx.org в этой ситуации не повышает безопасность, зато с высокой вероятностью ломает конфигурацию (см. §6.1).

Дополнительно:

```bash
apt-cache policy nginx        # какая версия доступна в репозитории
dpkg -l | grep -E 'nginx|openresty'
```

### 1.3 Docker

```bash
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep -iE 'nginx|openresty|proxy|ingress'
for c in $(docker ps -q); do
  printf '%s: ' "$(docker inspect -f '{{.Name}}' "$c")"
  docker exec "$c" nginx -v 2>&1 | head -1 || echo 'нет nginx'
done
docker images --format '{{.Repository}}:{{.Tag}}' | grep -iE 'nginx|openresty'
```

Compose-стеки и «спрятанный» nginx:

```bash
docker compose ls --all 2>/dev/null
find / -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' 2>/dev/null | grep -v '/proc/'
```

Не забудь про nginx внутри чужих образов — Remnawave, Nextcloud, GitLab, любой `*-webserver` сайдкар.

### 1.4 То, что пакетный менеджер не обновит

```bash
snap list nginx 2>/dev/null
kubectl get pods -A -o wide | grep ingress-nginx 2>/dev/null
nginx -V 2>&1 | grep -q -- '--prefix=/usr/local' && echo 'СБОРКА ИЗ ИСХОДНИКОВ'
```

---

## 2. Backup

Всё до единого изменения:

```bash
TS=$(date +%Y%m%d-%H%M%S); B=/var/backups/nginx-updater/$TS; mkdir -p "$B"

tar czf "$B/etc-nginx.tar.gz" -C / etc/nginx
cp -a /etc/nginx "$B/tree"                       # распакованное дерево для cp -an
nginx -V 2>&1 > "$B/nginx-V.txt"
dpkg -l | grep nginx > "$B/packages.txt"         # rpm -qa | grep nginx
ss -tlnp > "$B/listeners.txt"

for c in $(docker ps -q); do
  n=$(docker inspect -f '{{.Name}}' "$c" | tr -d /)
  docker inspect "$c" > "$B/docker-$n.json"
done
```

`nginx -V` сохраняем обязательно: если nginx собран из исходников, это единственный способ пересобрать его один в один.

---

## 3. Upgrade

### 3A. Debian/Ubuntu — репозиторий дистрибутива (пробовать **первым**)

Безопасный путь: `nginx.conf` не подменяется, layout `sites-available`/`sites-enabled` остаётся на месте.

```bash
apt-get update
apt-get install --only-upgrade -y nginx nginx-common nginx-core nginx-full nginx-light 2>/dev/null
zcat /usr/share/doc/nginx-common/changelog.Debian.gz | grep -m1 -A5 "$(dpkg-query -W -f='${Version}' nginx-common)"
```

Проверь по §1.2, закрылся ли CVE. Закрылся — на этом всё.

### 3B. Debian/Ubuntu — миграция на nginx.org

Только если дистрибутив реально отстаёт **и** остаточные CVE достаточно серьёзны. Это подмена вендора пакета, и она затрагивает конфигурацию.

```bash
apt-get install -y curl gnupg2 ca-certificates lsb-release

# ВАЖНО: проверить, что репозиторий для твоей пары (дистрибутив, кодовое имя) существует
. /etc/os-release
DIST=$ID; CODE=$VERSION_CODENAME
# derivatives (Mint, Pop!_OS, Astra, Kali) → маппинг на базовый Debian/Ubuntu
[ "$ID" = linuxmint ] && DIST=ubuntu && CODE=$UBUNTU_CODENAME
curl -fsI "https://nginx.org/packages/$DIST/dists/$CODE/Release" >/dev/null \
  && echo "репозиторий есть" || echo "НЕТ такого репозитория — не подключай, будет 404"

curl -fsSL https://nginx.org/keys/nginx_signing.key \
  | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
https://nginx.org/packages/$DIST $CODE nginx" > /etc/apt/sources.list.d/nginx.list

# приоритет, иначе apt может вернуться на пакет дистрибутива
printf 'Package: *\nPin: origin nginx.org\nPin-Priority: 900\n' > /etc/apt/preferences.d/99nginx

apt-get update
apt-get install -y nginx     # mainline: .../packages/mainline/$DIST
```

**Сразу после установки** — восстановить свою конфигурацию (см. §6.1).

### 3C. RHEL / Alma / Rocky / Oracle

```bash
cat > /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
priority=9
EOF
dnf -y install nginx || dnf -y upgrade nginx
```

`module_hotfixes=true` обязателен — иначе AppStream-модуль перебьёт репозиторий.

### 3D. Docker Compose

Плавающий тег:

```bash
cd /path/to/stack
docker compose pull && docker compose up -d
```

Запиненный тег — правь файл (и `.env`, если версия там):

```bash
cp docker-compose.yml docker-compose.yml.bak
sed -i 's|nginx:1\.25\.3-alpine|nginx:1.30.4-alpine|' docker-compose.yml
git diff docker-compose.yml          # посмотреть перед применением
docker compose up -d
```

Локальная сборка:

```bash
docker compose build --pull && docker compose up -d
```

`--pull` критичен: без него базовый слой `FROM nginx:...` возьмётся из локального кеша и ты пересоберёшь тот же уязвимый образ.

### 3E. Docker без compose

```bash
C=my-nginx
docker inspect "$C" > /tmp/$C.json      # ← источник истины по параметрам
docker pull nginx:1.30.4-alpine

# Проверить версию В ОБРАЗЕ до того, как трогать прод
docker run --rm --entrypoint nginx nginx:1.30.4-alpine -v

docker stop "$C"
docker rename "$C" "$C-preupgrade"      # НЕ rm — это твой откат

docker run -d --name "$C" \
  --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v /etc/nginx:/etc/nginx:ro \
  -v /var/www:/var/www:ro \
  --network my-net \
  nginx:1.30.4-alpine

docker exec "$C" nginx -t && curl -skI http://localhost/ | head -3
# ок → docker rm $C-preupgrade
# нет → docker rm -f $C && docker rename $C-preupgrade $C && docker start $C
```

Порты, тома, сети (с алиасами и статическими IP), env, capabilities, sysctl, ulimit — всё берётся из inspect. Ничего не восстанавливай по памяти.

### 3F. Сборка из исходников

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -- '--'   # сохранить флаги
curl -O https://nginx.org/download/nginx-1.30.4.tar.gz
tar xzf nginx-1.30.4.tar.gz && cd nginx-1.30.4
./configure <те же флаги>
make && make install
```

Динамические модули (`.so`) пересобирать той же версией — иначе `module is not binary compatible`.

---

## 4. Verify

```bash
nginx -v                                  # ≥ 1.30.4 stable / ≥ 1.31.3 mainline
nginx -t                                  # конфиг валиден
systemctl status nginx --no-pager
ss -tlnp | grep -E ':(80|443|8443) '      # сравнить с $B/listeners.txt
```

**Главная проверка — не версия и не `is-active`, а обслуживается ли то, что обслуживалось раньше.** nginx умеет быть «active» с пустой конфигурацией.

```bash
# Сколько server-блоков реально загружено
nginx -T 2>/dev/null | grep -c 'server_name'

# Конкретный домен в развёрнутой конфигурации
nginx -T 2>/dev/null | grep -c 'example.com'    # 0 = сайт НЕ обслуживается

# Дымовой тест по каждому слушающему порту
curl -skI http://127.0.0.1/       | head -3
curl -skI https://127.0.0.1/      | head -3
curl -skI -H 'Host: example.com' https://127.0.0.1/ | head -3

tail -n 50 /var/log/nginx/error.log
```

Ошибки первых минут после рестарта — там же (`journalctl -u nginx -n 50 --no-pager`).

---

## 5. Restart

```bash
nginx -t && systemctl restart nginx      # именно restart, не reload
docker compose restart                   # либо up -d, если менялся тег
```

---

## 6. Разбор нештатных ситуаций

### 6.1 После миграции на nginx.org пропали сайты

Симптом: `nginx -t` говорит «syntax is ok», сервис активен, но отдаётся дефолтная страница или 404. Причина: пакет nginx.org принёс свой `nginx.conf`, где есть только `include /etc/nginx/conf.d/*.conf`. Каталоги `sites-available`/`sites-enabled` — это соглашение Debian, апстрим о нём не знает.

Диагностика:

```bash
nginx -T 2>/dev/null | grep -c 'server_name'      # мало/ноль
grep -n 'include' /etc/nginx/nginx.conf
ls /etc/nginx/sites-enabled/                      # файлы на месте, но не подключены
```

Починка:

```bash
cp -a /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

# вставить ПЕРЕД закрывающей скобкой блока http{}
# (последняя строка вида "}" на нулевом уровне вложенности)
sed -i '$ s|^}|    include /etc/nginx/sites-enabled/*;\n}|' /etc/nginx/nginx.conf

nginx -t && systemctl restart nginx
nginx -T 2>/dev/null | grep -c 'server_name'      # теперь должно совпадать с числом ваших vhost
```

Если конфиги не сохранились вовсе — доставай из бэкапа `cp -an "$B/tree/." /etc/nginx/` (`-n` не затирает новые файлы пакета).

Если после вставки `nginx -t` падает — **проблема не в include, а в самих сайтах**. Читай ошибку: чаще всего это отсутствующий сертификат (сайт ссылается на путь, которого нет) или `listen [::]` на хосте без IPv6. Не убирай include обратно — чини причину.

### 6.2 apt/dnf ругается на conffile при миграции

```
Configuration file '/etc/nginx/nginx.conf'
 ==> Modified (by you or by a script) since installation.
```

Оставляй **свою** версию (`N` / keep), затем проверь совместимость с новым бинарником:

```bash
nginx -t
```

Не проходит — возьми дефолт от nginx.org и перенеси в него только свои директивы:

```bash
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.mine
cp /usr/share/nginx/nginx.conf.default /etc/nginx/nginx.conf 2>/dev/null
# перенести user, worker_processes, include-и
```

### 6.3 `unknown user "www-data"`

Пакет nginx.org работает от `nginx`, дистрибутивный — от `www-data`. После миграции конфиг ссылается на пользователя, которого нет.

```bash
useradd -r -s /usr/sbin/nologin -d /nonexistent www-data
chown -R www-data:www-data /var/cache/nginx /var/lib/nginx 2>/dev/null
```

Либо поменяй `user` в `nginx.conf` — но тогда проверь права на кеш, сокеты и загрузочные каталоги.

### 6.4 `dlopen() ... failed` / модуль не грузится

```bash
nginx -t 2>&1 | grep -E 'dlopen|load_module'
```

Пути в `load_module` резолвятся относительно `--modules-path` (обычно `/usr/lib/nginx/modules`), **не** относительно `/etc/nginx`. Смотри:

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep modules-path
ls /usr/lib/nginx/modules/
```

Модуля нет в новом пакете (типично для `nginx-extras` → nginx.org) — отключи файл, который его подключает:

```bash
mv /etc/nginx/modules-enabled/50-mod-http-echo.conf{,.disabled}
nginx -t
```

Модуль нужен — ставь `nginx-module-*` из репозитория nginx.org или собирай под новую версию.

### 6.5 Предупреждение про `listen ... http2`

С 1.25.1 директива `listen 443 ssl http2;` устарела:

```
nginx: [warn] the "listen ... http2" directive is deprecated, use the "http2" directive instead
```

```nginx
server {
    listen 443 ssl;
    http2 on;
    ...
}
```

Переписывай **только в server-блоках, где все `listen` идут с `ssl`**. Иначе `http2 on;` включит h2c на plaintext-порту, и часть клиентов отвалится.

### 6.6 Откат

Debian/Ubuntu:

```bash
grep nginx "$B/packages.txt"          # версия, которая была
apt-get install -y --allow-downgrades nginx=1.24.0-2ubuntu7.15
apt-mark hold nginx

# совсем плохо — конфиг целиком
systemctl stop nginx
rm -rf /etc/nginx && tar xzf "$B/etc-nginx.tar.gz" -C /
nginx -t && systemctl start nginx
```

Убрать репозиторий nginx.org, если возвращаешься на дистрибутивный:

```bash
rm -f /etc/apt/sources.list.d/nginx.list /etc/apt/preferences.d/99nginx
apt-get update
```

Docker:

```bash
docker rm -f my-nginx
docker rename my-nginx-preupgrade my-nginx
docker start my-nginx
# compose:
cp docker-compose.yml.bak docker-compose.yml && docker compose up -d
```

---

## 7. Частные случаи

### 7.1 nginx как fallback за Reality/XTLS

nginx слушает `127.0.0.1:8443`, трафик на него форвардит Xray:

- контракт `listen 127.0.0.1:8443` не менять — форвард идёт именно туда;
- TLS 1.3 / X25519 / OCSP stapling живут в конфиге, не в пакете — бэкап уже снят на §2;
- пока нода выключена, на 443 торчит сам nginx → такой сервер патчится **первым**;
- после рестарта: `ss -tlnp | grep '127.0.0.1:8443'`;
- проверь расписание acme.sh — деплой-хук с перезапуском nginx не должен попасть в то же окно.

### 7.2 ingress-nginx

Проект Kubernetes закрыт в марте 2026, апстрим-патча не будет. Варианты: миграция на Gateway API (`ingate`), коммерческий форк или своя сборка. Скрипт такое только детектит.

### 7.3 nginx из snap

```bash
snap refresh nginx
```

Своя система обновлений, apt/dnf его не видят.

---

## 8. Чеклист на сервер

```
[ ] Inventory снят (системный + docker + скрытый)
[ ] Проверен бэкпорт дистрибутива (§1.2) — возможно, делать нечего
[ ] Бэкап: /etc/nginx (tar + дерево), nginx -V, список пакетов, docker inspect
[ ] Обновление: сначала репозиторий дистрибутива
[ ] Если мигрировали на nginx.org — конфигурация восстановлена, include проверены
[ ] nginx -T | grep -c server_name  == числу vhost до апгрейда
[ ] Дымовой тест по каждому слушающему порту
[ ] Полный restart (не reload)
[ ] error.log чист в первые минуты
[ ] Docker-контейнеры: версия в контейнере, nginx -t, ответ curl
[ ] -preupgrade контейнеры удалены после подтверждения
```

---

## 9. Одной портянкой

```bash
# статус
nginx -v; nginx -t; ss -tlnp | grep nginx
zcat /usr/share/doc/nginx-common/changelog.Debian.gz | grep -oE 'CVE-[0-9-]+' | sort -u | head

# обновление по-хорошему
apt-get update && apt-get install --only-upgrade -y nginx nginx-common nginx-core

# проверка, что сайты живы
nginx -T 2>/dev/null | grep -c server_name
curl -skI https://127.0.0.1/ | head -3

# docker
docker ps --format '{{.Names}} {{.Image}}' | grep -i nginx
docker compose pull && docker compose up -d
```
