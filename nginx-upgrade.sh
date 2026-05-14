#!/usr/bin/env bash
#
# nginx-upgrade.sh — массовый апгрейд nginx под CVE-2026-42945 (NGINX Rift)
#
# Поддерживает:
#   * Системный nginx на Debian/Ubuntu (через nginx.org repo)
#   * Системный nginx на RHEL/Alma/Rocky/Oracle (через nginx.org repo)
#   * Docker контейнеры, запущенные через docker compose
#   * Detection для raw `docker run` контейнеров (с инструкцией для ручного апдейта)
#
# Использование:
#   ./nginx-upgrade.sh                # выполнить апгрейд
#   ./nginx-upgrade.sh --check        # dry-run: только отчёт, без изменений
#   ./nginx-upgrade.sh --skip-docker  # только системный nginx
#   ./nginx-upgrade.sh --skip-system  # только Docker
#   ./nginx-upgrade.sh --mainline     # ставить ветку mainline (1.31.x), по умолчанию stable (1.30.x)
#   ./nginx-upgrade.sh --help
#
# Exit codes:
#   0 — всё ок (или ничего делать не нужно)
#   1 — фатальная ошибка
#   2 — частичный успех (что-то требует ручной работы)

set -euo pipefail

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

readonly MIN_SAFE_STABLE="1.30.1"
readonly MIN_SAFE_MAINLINE="1.31.0"
readonly LOG_DIR="/var/log/nginx-upgrade"
readonly BACKUP_ROOT="/root"

NGINX_TRACK="stable"        # stable | mainline
DRY_RUN=false
SKIP_SYSTEM=false
SKIP_DOCKER=false
EXIT_CODE=0
NEEDS_MANUAL=()             # список контейнеров/мест, требующих ручной работы

# ============================================================================
# CLI
# ============================================================================

usage() {
  sed -n '2,/^# Exit codes:/p' "$0" | sed 's/^#//; s/^ //'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check|--dry-run)  DRY_RUN=true ;;
    --skip-system)      SKIP_SYSTEM=true ;;
    --skip-docker)      SKIP_DOCKER=true ;;
    --mainline)         NGINX_TRACK="mainline" ;;
    --stable)           NGINX_TRACK="stable" ;;
    -h|--help)          usage ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
  shift
done

# ============================================================================
# ЛОГИРОВАНИЕ
# ============================================================================

mkdir -p "$LOG_DIR"
readonly LOG_FILE="$LOG_DIR/upgrade-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -t 1 ]]; then
  RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; BLUE=$'\e[34m'
  BOLD=$'\e[1m'; DIM=$'\e[2m'; NC=$'\e[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; DIM=""; NC=""
fi

log()    { echo "${DIM}[$(date +%T)]${NC} $*"; }
ok()     { echo "${GREEN}[$(date +%T)] ✓${NC} $*"; }
warn()   { echo "${YELLOW}[$(date +%T)] ⚠${NC} $*"; }
err()    { echo "${RED}[$(date +%T)] ✗${NC} $*" >&2; }
header() { echo; echo "${BOLD}═══ $* ═══${NC}"; }

trap 'err "Fatal error at line $LINENO (exit $?). Лог: $LOG_FILE"; exit 1' ERR

# ============================================================================
# HELPERS
# ============================================================================

# version_lt 1.30.0 1.30.1 → exit 0 (true)
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

# Уязвимы все версии < 1.30.1 (фикс в 1.30.1 и 1.31.0+)
is_vulnerable() {
  local v="${1:-}"
  [[ -z "$v" || "$v" == "unknown" ]] && return 1
  version_lt "$v" "$MIN_SAFE_STABLE"
}

get_version_from_cmd() {
  # читает stderr `nginx -v` и выдёргивает X.Y.Z
  "$@" 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo "unknown"
}

restart_system_nginx() {
  if command -v systemctl >/dev/null && systemctl list-unit-files 2>/dev/null | grep -q '^nginx\.service'; then
    systemctl restart nginx
  elif command -v service >/dev/null; then
    service nginx restart
  else
    err "Не нашёл способа перезапустить системный nginx"
    return 1
  fi
}

# ============================================================================
# PHASE 1: PRE-FLIGHT
# ============================================================================

header "Phase 1: Pre-flight"

if [[ $EUID -ne 0 ]]; then
  err "Скрипт должен запускаться от root (или через sudo)"
  exit 1
fi
ok "Запущен от root"

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
log "Хост: $HOSTNAME_FQDN"
log "Режим: $($DRY_RUN && echo 'DRY-RUN (изменения не делаются)' || echo 'APPLY')"
log "Ветка nginx: $NGINX_TRACK"

OS_ID="unknown"; OS_CODENAME=""
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_CODENAME="${VERSION_CODENAME:-}"
  log "OS: ${PRETTY_NAME:-$OS_ID}"
fi

HAS_SYSTEM_NGINX=false
if command -v nginx >/dev/null 2>&1; then
  HAS_SYSTEM_NGINX=true
fi

HAS_DOCKER=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  HAS_DOCKER=true
fi

if ! $HAS_SYSTEM_NGINX && ! $HAS_DOCKER; then
  log "Ни системного nginx, ни Docker не найдено. Выхожу."
  exit 0
fi

BACKUP_DIR="$BACKUP_ROOT/nginx-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
log "Backup directory: $BACKUP_DIR"

# ============================================================================
# PHASE 2: INVENTORY
# ============================================================================

header "Phase 2: Inventory"

SYSTEM_VERSION=""
if $HAS_SYSTEM_NGINX; then
  SYSTEM_VERSION="$(get_version_from_cmd nginx -v)"
  if is_vulnerable "$SYSTEM_VERSION"; then
    warn "Системный nginx: $SYSTEM_VERSION (УЯЗВИМ)"
  else
    ok   "Системный nginx: $SYSTEM_VERSION (ок)"
  fi
fi

declare -a DOCKER_NGINX=()      # имена контейнеров с nginx внутри
if $HAS_DOCKER; then
  while IFS= read -r cname; do
    [[ -z "$cname" ]] && continue
    if docker exec "$cname" sh -c 'command -v nginx >/dev/null 2>&1' 2>/dev/null; then
      DOCKER_NGINX+=("$cname")
      cv="$(docker exec "$cname" nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo unknown)"
      if is_vulnerable "$cv"; then
        warn "Docker: $cname (nginx $cv) (УЯЗВИМ)"
      else
        ok   "Docker: $cname (nginx $cv) (ок)"
      fi
    fi
  done < <(docker ps --format '{{.Names}}' 2>/dev/null)

  if [[ ${#DOCKER_NGINX[@]} -eq 0 ]]; then
    log "Контейнеры с nginx не найдены"
  fi
fi

# ============================================================================
# PHASE 3: SYSTEM NGINX UPGRADE
# ============================================================================

upgrade_system_debian() {
  if ! grep -rhq 'nginx\.org' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    log "nginx.org репозиторий не подключён — добавляю ($NGINX_TRACK)"
    curl -fsSL https://nginx.org/keys/nginx_signing.key \
      | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

    local path_segment="packages"
    [[ "$NGINX_TRACK" == "mainline" ]] && path_segment="packages/mainline"

    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/${path_segment}/${OS_ID} ${OS_CODENAME} nginx" \
      > /etc/apt/sources.list.d/nginx.list
    ok "Репозиторий добавлен"
  fi

  dpkg -l 'nginx*' > "$BACKUP_DIR/packages-before.txt" 2>/dev/null || true
  apt-get update -qq
  log "Candidate: $(apt-cache policy nginx | awk '/Candidate:/ {print $2}')"
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::='--force-confold' \
    -o Dpkg::Options::='--force-confdef' \
    nginx
}

upgrade_system_rhel() {
  if [[ ! -f /etc/yum.repos.d/nginx.repo ]]; then
    log "nginx.org репозиторий не подключён — добавляю ($NGINX_TRACK)"
    local path_segment=""
    [[ "$NGINX_TRACK" == "mainline" ]] && path_segment="mainline/"

    cat > /etc/yum.repos.d/nginx.repo <<EOF
[nginx-${NGINX_TRACK}]
name=nginx ${NGINX_TRACK} repo
baseurl=http://nginx.org/packages/${path_segment}centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
    ok "Репозиторий добавлен"
  fi

  rpm -qa 'nginx*' > "$BACKUP_DIR/packages-before.txt" 2>/dev/null || true
  dnf clean all -q
  dnf install -y nginx
}

upgrade_system() {
  header "Phase 3: System nginx"

  if $SKIP_SYSTEM; then
    log "--skip-system → пропуск"
    return 0
  fi

  if ! $HAS_SYSTEM_NGINX; then
    log "Системный nginx не установлен → пропуск"
    return 0
  fi

  if ! is_vulnerable "$SYSTEM_VERSION"; then
    ok "Системный nginx $SYSTEM_VERSION уже не уязвим → пропуск"
    return 0
  fi

  if $DRY_RUN; then
    warn "[DRY-RUN] Был бы выполнен апгрейд системного nginx ($SYSTEM_VERSION → ≥${MIN_SAFE_STABLE})"
    return 0
  fi

  log "Бэкаплю /etc/nginx → $BACKUP_DIR/nginx-conf.tgz"
  tar czf "$BACKUP_DIR/nginx-conf.tgz" -C / etc/nginx 2>/dev/null || true

  case "$OS_ID" in
    debian|ubuntu)
      upgrade_system_debian
      ;;
    rhel|centos|almalinux|rocky|ol|fedora)
      upgrade_system_rhel
      ;;
    *)
      err "Неподдерживаемая OS: $OS_ID. Системный апгрейд пропущен."
      NEEDS_MANUAL+=("System nginx ($OS_ID — OS не поддержана автоматически)")
      EXIT_CODE=2
      return 1
      ;;
  esac

  # Проверяем конфиг ДО рестарта
  if ! nginx -t 2>&1; then
    err "nginx -t упал после установки нового пакета! НЕ перезапускаю."
    err "Конфиг — в $BACKUP_DIR/nginx-conf.tgz"
    EXIT_CODE=1
    return 1
  fi
  ok "nginx -t OK"

  # Полный restart, не reload
  log "systemctl restart nginx"
  if ! restart_system_nginx; then
    EXIT_CODE=1
    return 1
  fi
  sleep 2

  if command -v systemctl >/dev/null && ! systemctl is-active --quiet nginx; then
    err "nginx не стартанул!"
    EXIT_CODE=1
    return 1
  fi

  local new_v
  new_v="$(get_version_from_cmd nginx -v)"
  if is_vulnerable "$new_v"; then
    err "Версия после апгрейда всё ещё уязвима: $new_v"
    EXIT_CODE=1
    return 1
  fi

  ok "Системный nginx: $SYSTEM_VERSION → $new_v"
}

# ============================================================================
# PHASE 4: DOCKER
# ============================================================================

upgrade_compose_service() {
  local project_dir="$1"
  local service_name="$2"
  local container_name="$3"

  log "  compose проект: $project_dir, сервис: $service_name"

  local compose_file=""
  for f in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
    if [[ -f "$project_dir/$f" ]]; then
      compose_file="$project_dir/$f"
      break
    fi
  done

  if [[ -z "$compose_file" ]]; then
    warn "  compose файл не найден в $project_dir → ручное обновление"
    NEEDS_MANUAL+=("$container_name (compose файл не найден в $project_dir)")
    EXIT_CODE=2
    return 1
  fi

  # Проверка на запиненную версию в compose
  local image_line
  image_line="$(awk -v svc="$service_name" '
    $0 ~ "^[[:space:]]*"svc":" {in_svc=1; next}
    in_svc && /^[a-zA-Z]/ {in_svc=0}
    in_svc && /image:/ {print; exit}
  ' "$compose_file" || true)"

  if echo "$image_line" | grep -qE 'image:[[:space:]]*[\x27"]?(library/)?(nginx|openresty):[0-9]+\.[0-9]+'; then
    warn "  В $compose_file тег запинен: $(echo "$image_line" | xargs)"
    warn "  docker compose pull НЕ возьмёт свежий образ. Обнови тег вручную."
    NEEDS_MANUAL+=("$container_name (запинен тег в $compose_file)")
    EXIT_CODE=2
    return 1
  fi

  if $DRY_RUN; then
    warn "  [DRY-RUN] docker compose pull $service_name && docker compose up -d $service_name"
    return 0
  fi

  ( cd "$project_dir" && docker compose pull "$service_name" )
  ( cd "$project_dir" && docker compose up -d "$service_name" )
  sleep 3

  # Проверка
  if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
    # имя контейнера могло поменяться после recreate — пробуем найти по compose-меткам
    local new_cname
    new_cname="$(docker ps --filter "label=com.docker.compose.project.working_dir=$project_dir" \
                            --filter "label=com.docker.compose.service=$service_name" \
                            --format '{{.Names}}' | head -n1)"
    if [[ -n "$new_cname" ]]; then
      container_name="$new_cname"
    fi
  fi

  if ! docker exec "$container_name" nginx -t >/dev/null 2>&1; then
    err "  nginx -t упал в контейнере $container_name"
    EXIT_CODE=1
    return 1
  fi

  local new_v
  new_v="$(docker exec "$container_name" nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  if is_vulnerable "$new_v"; then
    err "  Версия в $container_name всё ещё уязвима: $new_v"
    EXIT_CODE=1
    return 1
  fi

  ok "  $container_name → nginx $new_v"
}

upgrade_docker() {
  header "Phase 4: Docker containers"

  if $SKIP_DOCKER; then
    log "--skip-docker → пропуск"
    return 0
  fi

  if ! $HAS_DOCKER; then
    log "Docker не запущен → пропуск"
    return 0
  fi

  if [[ ${#DOCKER_NGINX[@]} -eq 0 ]]; then
    log "Контейнеров с nginx нет → пропуск"
    return 0
  fi

  for cname in "${DOCKER_NGINX[@]}"; do
    log "Контейнер: $cname"
    local cversion
    cversion="$(docker exec "$cname" nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo unknown)"

    if ! is_vulnerable "$cversion"; then
      ok "  $cname (nginx $cversion) — не уязвим, пропуск"
      continue
    fi

    if $DRY_RUN; then
      warn "  [DRY-RUN] $cname (nginx $cversion) — был бы обновлён"
      continue
    fi

    # Бэкап inspect для отката
    docker inspect "$cname" > "$BACKUP_DIR/inspect-$cname.json" 2>/dev/null || true

    # Compose-managed?
    local proj_dir proj_service
    proj_dir="$(docker inspect "$cname" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null || true)"
    proj_service="$(docker inspect "$cname" --format '{{ index .Config.Labels "com.docker.compose.service" }}' 2>/dev/null || true)"

    if [[ -n "$proj_dir" && -n "$proj_service" && -d "$proj_dir" ]]; then
      upgrade_compose_service "$proj_dir" "$proj_service" "$cname" || true
    else
      warn "  $cname — не compose (raw docker run). Авто-обновление требует точного повторения параметров запуска и небезопасно."
      warn "  Inspect сохранён в $BACKUP_DIR/inspect-$cname.json — обнови по runbook'у вручную."
      NEEDS_MANUAL+=("$cname (raw docker run — см. $BACKUP_DIR/inspect-$cname.json)")
      EXIT_CODE=2
    fi
  done
}

# ============================================================================
# PHASE 5: SUMMARY
# ============================================================================

print_summary() {
  header "Summary"
  echo
  echo "${BOLD}Хост:${NC}    $HOSTNAME_FQDN"
  echo "${BOLD}Лог:${NC}     $LOG_FILE"
  echo "${BOLD}Backup:${NC}  $BACKUP_DIR"
  echo

  if $HAS_SYSTEM_NGINX; then
    local v
    v="$(get_version_from_cmd nginx -v)"
    if is_vulnerable "$v"; then
      echo "  System nginx:  ${RED}$v (УЯЗВИМ)${NC}"
    else
      echo "  System nginx:  ${GREEN}$v ✓${NC}"
    fi
  fi

  for cname in "${DOCKER_NGINX[@]}"; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${cname}$"; then
      local cv
      cv="$(docker exec "$cname" nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo unknown)"
      if is_vulnerable "$cv"; then
        echo "  Docker $cname:  ${RED}$cv (УЯЗВИМ)${NC}"
      else
        echo "  Docker $cname:  ${GREEN}$cv ✓${NC}"
      fi
    fi
  done

  if [[ ${#NEEDS_MANUAL[@]} -gt 0 ]]; then
    echo
    echo "${YELLOW}${BOLD}Требуют ручной работы:${NC}"
    for item in "${NEEDS_MANUAL[@]}"; do
      echo "  ⚠ $item"
    done
  fi

  echo
  case "$EXIT_CODE" in
    0) echo "${GREEN}${BOLD}РЕЗУЛЬТАТ: OK${NC}" ;;
    1) echo "${RED}${BOLD}РЕЗУЛЬТАТ: ОШИБКА${NC}" ;;
    2) echo "${YELLOW}${BOLD}РЕЗУЛЬТАТ: ЧАСТИЧНО (см. ручную работу выше)${NC}" ;;
  esac
}

# ============================================================================
# MAIN
# ============================================================================

upgrade_system || true
upgrade_docker || true
print_summary

exit $EXIT_CODE
