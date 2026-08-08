#!/usr/bin/env bash
#
# nginx-upgrade.sh — автоматический патчер nginx под текущую волну CVE
#                    (NGINX Rift CVE-2026-42945 и всё, что вышло после)
#
# Что делает сам, без участия человека:
#   * определяет, пропатчен ли nginx НА САМОМ ДЕЛЕ (учитывает бэкпорты дистрибутива,
#     а не только вывод `nginx -v`)
#   * обновляет системный nginx: сначала штатным репозиторием дистрибутива,
#     и только если тот не может закрыть дыру — мигрирует на nginx.org
#   * при миграции сохраняет и восстанавливает ВСЮ конфигурацию, включая
#     sites-available / sites-enabled / conf.d / snippets / сертификаты
#   * чинит nginx.conf: include sites-enabled, include conf.d, отсутствующий
#     системный пользователь, битые modules-enabled, deprecated `listen ... http2`
#   * снимает слепок слушающих сокетов до апгрейда и откатывается сам,
#     если после апгрейда сайт перестал отвечать
#   * обновляет nginx в Docker: compose (в т.ч. с запиненным тегом и с локальной
#     сборкой) и обычные `docker run` — с пересозданием по слепку inspect
#
# Использование:
#   ./nginx-upgrade.sh                   применить
#   ./nginx-upgrade.sh --check           только отчёт, ничего не менять
#   ./nginx-upgrade.sh --json /tmp/r.json
#   ./nginx-upgrade.sh --install-timer   поставить systemd-таймер (ежедневная проверка)
#   ./nginx-upgrade.sh --help
#
# Exit codes:
#   0 — всё чисто (или чинить было нечего)
#   1 — фатальная ошибка / что-то осталось уязвимым
#   2 — частичный успех, есть пункты для ручной работы
#
# https://github.com/tagashi666/nginx-updater      MIT

set -uo pipefail

readonly SCRIPT_VERSION="2.0.1"
readonly SCRIPT_SELF="${BASH_SOURCE[0]}"

# ============================================================================
# БАЗА УЯЗВИМОСТЕЙ (источник: https://nginx.org/en/security_advisories.html)
#
# Формат: CVE|severity|уязвимые диапазоны|версии-с-фиксом
#   severity: critical|major|medium|low   (critical — наша оценка, не F5)
#   диапазоны: "A-B" или "A", через запятую
#   фиксы: "X.Y.Z" через запятую — означает "X.Y.Z и новее В ЭТОЙ ВЕТКЕ X.Y"
#
# Правило: версия уязвима, если попадает в диапазон И её ветка не покрыта фиксом.
# Слепок на 2026-08-07. Скрипт умеет обновлять эту базу онлайн (--refresh).
# ============================================================================

CVE_DB="$(cat <<'__CVEDB__'
CVE-2026-42533|major|0.9.6-1.31.2|1.31.3,1.30.4
CVE-2026-60005|medium|1.15.8-1.31.2|1.31.3,1.30.4
CVE-2026-56434|medium|0.8.11-1.31.2|1.31.3,1.30.4
CVE-2026-42530|major|1.31.0-1.31.1|1.31.2
CVE-2026-42055|medium|1.13.10-1.31.1|1.31.2,1.30.3
CVE-2026-48142|low|0.3.50-1.31.1|1.31.2,1.30.3
CVE-2026-9256|medium|0.1.17-1.31.0|1.31.1,1.30.2
CVE-2026-42945|critical|0.6.27-1.30.0|1.31.0,1.30.1
CVE-2026-42926|medium|1.29.4-1.30.0|1.31.0,1.30.1
CVE-2026-42946|medium|0.8.42-1.30.0|1.31.0,1.30.1
CVE-2026-42934|low|0.3.50-1.30.0|1.31.0,1.30.1
CVE-2026-40460|medium|1.25.0-1.30.0|1.31.0,1.30.1
CVE-2026-40701|medium|1.19.0-1.30.0|1.31.0,1.30.1
CVE-2026-27654|medium|0.5.13-1.29.6|1.29.7,1.28.3
CVE-2026-27784|medium|1.1.19-1.29.6|1.29.7,1.28.3
CVE-2026-32647|medium|1.1.19-1.29.6|1.29.7,1.28.3
CVE-2026-27651|low|0.5.15-1.29.6|1.29.7,1.28.3
CVE-2026-28753|medium|0.6.27-1.29.6|1.29.7,1.28.3
CVE-2026-28755|medium|1.27.2-1.29.6|1.29.7,1.28.3
CVE-2026-1642|medium|1.3.0-1.29.4|1.29.5,1.28.2
CVE-2025-53859|low|0.7.22-1.29.0|1.29.1
CVE-2025-23419|medium|1.11.4-1.27.3|1.27.4,1.26.3
CVE-2024-7347|low|1.5.13-1.27.0|1.27.1,1.26.2
CVE-2021-23017|major|0.6.18-1.20.0|1.21.0,1.20.1
__CVEDB__
)"

# Целевые версии по умолчанию (пересчитываются из CVE_DB, здесь — для справки)
readonly TARGET_STABLE="1.30.4"
readonly TARGET_MAINLINE="1.31.3"

readonly LOG_DIR="/var/log/nginx-upgrade"
readonly BACKUP_ROOT="/var/backups/nginx-updater"
readonly ADVISORY_URL="https://nginx.org/en/security_advisories.html"

# ============================================================================
# ФЛАГИ
# ============================================================================

NGINX_TRACK="stable"
DRY_RUN=false
SKIP_SYSTEM=false
SKIP_DOCKER=false
DISTRO_ONLY=false          # никогда не подключать nginx.org
PREFER_UPSTREAM=false      # сразу идти на nginx.org
ALLOW_RECREATE=true        # пересоздавать raw docker run контейнеры
FIX_CONFIG=true            # чинить nginx.conf
FIX_HTTP2=true             # мигрировать listen ... http2 → http2 on
AUTO_ROLLBACK=true
REFRESH_DB=true            # тянуть свежий список CVE с nginx.org
QUIET=false
JSON_OUT=""
WEBHOOK="${NGXUP_WEBHOOK:-}"
MIGRATE_SEVERITY="major"   # что заставляет мигрировать на nginx.org

EXIT_CODE=0
NEEDS_MANUAL=()
NEEDS_MANUAL_N=0
ACTIONS=()
ACTIONS_N=0

usage() {
  cat <<'__USAGE__'
nginx-upgrade.sh — автоматический патчер nginx (CVE-2026-42945 NGINX Rift и новее)

  ./nginx-upgrade.sh [флаги]

ОСНОВНОЕ
  --check, --dry-run     ничего не менять, только показать план
  --json ФАЙЛ            записать машиночитаемый отчёт
  --quiet                меньше болтовни (для cron)
  -h, --help             эта справка
  --version              версия скрипта

ЧТО ТРОГАТЬ
  --skip-system          не трогать системный nginx
  --skip-docker          не трогать контейнеры
  --no-recreate          не пересоздавать raw `docker run` контейнеры
  --no-fix-config        не чинить nginx.conf (include, user, modules)
  --no-fix-http2         не мигрировать `listen ... http2` → `http2 on`
  --no-rollback          не откатываться автоматически при поломке

ИСТОЧНИК ПАКЕТОВ
  --distro-only          только репозиторий дистрибутива, nginx.org не подключать
  --prefer-upstream      сразу ставить с nginx.org, не пытаясь через дистрибутив
  --stable               ветка stable (по умолчанию)
  --mainline             ветка mainline
  --severity LEVEL       порог для миграции на nginx.org: critical|major|medium|low
                         (по умолчанию major)
  --no-refresh           не обновлять список CVE с nginx.org, использовать встроенный

ОБСЛУЖИВАНИЕ
  --install-timer        поставить systemd-таймер ежедневной проверки
  --uninstall-timer      снять таймер

ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ
  NGXUP_WEBHOOK=URL      POST-нуть JSON-отчёт после прогона

КОДЫ ВОЗВРАТА
  0 — чисто    1 — ошибка / осталось уязвимое    2 — нужна ручная работа
__USAGE__
  exit 0
}

DO_TIMER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check|--dry-run)  DRY_RUN=true ;;
    --skip-system)      SKIP_SYSTEM=true ;;
    --skip-docker)      SKIP_DOCKER=true ;;
    --no-recreate)      ALLOW_RECREATE=false ;;
    --no-fix-config)    FIX_CONFIG=false ;;
    --no-fix-http2)     FIX_HTTP2=false ;;
    --no-rollback)      AUTO_ROLLBACK=false ;;
    --no-refresh)       REFRESH_DB=false ;;
    --distro-only)      DISTRO_ONLY=true ;;
    --prefer-upstream)  PREFER_UPSTREAM=true ;;
    --mainline)         NGINX_TRACK="mainline" ;;
    --stable)           NGINX_TRACK="stable" ;;
    --quiet)            QUIET=true ;;
    --severity)         MIGRATE_SEVERITY="${2:-major}"; shift ;;
    --severity=*)       MIGRATE_SEVERITY="${1#*=}" ;;
    --json)             JSON_OUT="${2:-}"; shift ;;
    --json=*)           JSON_OUT="${1#*=}" ;;
    --webhook)          WEBHOOK="${2:-}"; shift ;;
    --webhook=*)        WEBHOOK="${1#*=}" ;;
    --install-timer)    DO_TIMER="install" ;;
    --uninstall-timer)  DO_TIMER="uninstall" ;;
    --version)          echo "nginx-upgrade.sh $SCRIPT_VERSION"; exit 0 ;;
    -h|--help)          usage ;;
    *) echo "Неизвестный аргумент: $1 (см. --help)" >&2; exit 1 ;;
  esac
  shift
done

# ============================================================================
# BOOTSTRAP: root-check, цвета, лог-файл
# Вынесено в функцию, чтобы скрипт можно было `source` без побочных эффектов
# ============================================================================

RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; DIM=""; NC=""
LOG_FILE="/dev/null"
LOG_FLUSHED=false

bootstrap() {
  # ============================================================================
  # ROOT — проверяем ДО любых mkdir, иначе юзер получит невнятную ошибку
  # ============================================================================

  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "nginx-upgrade.sh: нужен root. Запусти через sudo." >&2
    exit 1
  fi

  if [[ -z "${BASH_VERSINFO:-}" || ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo "nginx-upgrade.sh: нужен bash >= 4. Запусти как 'bash nginx-upgrade.sh'." >&2
    exit 1
  fi

  # ============================================================================
  # ЦВЕТА И ЛОГИ
  # Цвет определяем ДО подмены stdout на pipe — иначе цветов не будет никогда
  # ============================================================================

  if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]] && [[ -z "${NO_COLOR:-}" ]]; then
    RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'
    BOLD=$'\e[1m'; DIM=$'\e[2m'; NC=$'\e[0m'
  else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; DIM=""; NC=""
  fi

  mkdir -p "$LOG_DIR" 2>/dev/null || true
  LOG_FILE="$LOG_DIR/upgrade-$(date +%Y%m%d-%H%M%S).log"
  if [[ ! -d "$LOG_DIR" ]]; then
    LOG_FILE="$(mktemp -t nginx-upgrade-XXXXXX.log)"
  fi

  exec 3>&1 4>&2
  exec > >(tee -a "$LOG_FILE") 2>&1
  TEE_PID=$!
  trap flush_log EXIT


}

flush_log() {
  $LOG_FLUSHED && return 0
  LOG_FLUSHED=true
  if { true >&3; } 2>/dev/null; then exec 1>&3 2>&4; fi
  [[ -n "${TEE_PID:-}" ]] && wait "$TEE_PID" 2>/dev/null
  return 0
}

log()    { $QUIET && return 0; echo "${DIM}[$(date +%T)]${NC} $*"; }
ok()     { $QUIET && return 0; echo "${GREEN}[$(date +%T)] ✓${NC} $*"; }
warn()   { echo "${YELLOW}[$(date +%T)] ⚠${NC} $*"; }
err()    { echo "${RED}[$(date +%T)] ✗${NC} $*" >&2; }
header() { $QUIET && return 0; echo; echo "${BOLD}═══ $* ═══${NC}"; }
note()   { $QUIET && return 0; echo "   ${CYAN}→${NC} $*"; }

die() { err "$*"; EXIT_CODE=1; print_summary 2>/dev/null || true; flush_log; exit 1; }

manual() { NEEDS_MANUAL+=("$1"); NEEDS_MANUAL_N=$((NEEDS_MANUAL_N + 1)); [[ $EXIT_CODE -eq 0 ]] && EXIT_CODE=2; return 0; }

# Снять пометки, потерявшие смысл. Пример: до апгрейда записали «патч дистрибутива
# отозван», потом успешно уехали на nginx.org — CVE закрыт, а пометка висит и
# превращает честное «ЧИСТО» в пугающее «ЧАСТИЧНО».
manual_drop() {
  local pat="$1" keep=() m
  for m in ${NEEDS_MANUAL[@]+"${NEEDS_MANUAL[@]}"}; do
    [[ "$m" == *"$pat"* ]] || keep+=("$m")
  done
  NEEDS_MANUAL=(${keep[@]+"${keep[@]}"})
  NEEDS_MANUAL_N=${#NEEDS_MANUAL[@]}
  [[ $NEEDS_MANUAL_N -eq 0 && $EXIT_CODE -eq 2 ]] && EXIT_CODE=0
  return 0
}
acted()  { ACTIONS+=("$1"); ACTIONS_N=$((ACTIONS_N + 1)); return 0; }

# ============================================================================
# СРАВНЕНИЕ ВЕРСИЙ И ОЦЕНКА УЯЗВИМОСТИ
# ============================================================================

# -1 / 0 / 1
ver_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    gsub(/[^0-9.]/,"",a); gsub(/[^0-9.]/,"",b);
    na=split(a,A,"."); nb=split(b,B,".");
    n=(na>nb)?na:nb;
    for(i=1;i<=n;i++){
      x=(i<=na)?A[i]+0:0; y=(i<=nb)?B[i]+0:0;
      if(x<y){print -1; exit} if(x>y){print 1; exit}
    }
    print 0}'
}
ver_ge() { [[ "$(ver_cmp "$1" "$2")" != "-1" ]]; }
ver_gt() { [[ "$(ver_cmp "$1" "$2")" == "1" ]]; }

# 1.30.4 → 1.30
ver_branch() {
  local v="$1"
  echo "${v%.*}"
}

# in_range 1.24.0 "0.6.27-1.30.0,1.0.7-1.0.15"
in_range() {
  local v="$1" item lo hi
  local -a items
  read -r -a items <<< "${2//,/ }"
  for item in "${items[@]:-}"; do
    [[ -z "$item" ]] && continue
    if [[ "$item" == *-* ]]; then
      lo="${item%%-*}"; hi="${item##*-}"
      if ver_ge "$v" "$lo" && ver_ge "$hi" "$v"; then return 0; fi
    else
      if [[ "$(ver_cmp "$v" "$item")" == "0" ]]; then return 0; fi
    fi
  done
  return 1
}

# Покрыта ли версия фиксом. fixed_spec="1.31.0,1.30.1"
branch_is_fixed() {
  local v="$1" item vb ib maxb=""
  local -a items
  vb="$(ver_branch "$v")"
  read -r -a items <<< "${2//,/ }"
  for item in "${items[@]:-}"; do
    [[ -z "$item" || "$item" == "none" ]] && continue
    ib="$(ver_branch "$item")"
    if [[ -z "$maxb" ]] || ver_gt "$ib" "$maxb"; then maxb="$ib"; fi
    if [[ "$vb" == "$ib" ]]; then
      ver_ge "$v" "$item" && return 0
      return 1
    fi
  done
  # ветки нет в списке фиксов: считаем безопасной только если она новее всех
  [[ -n "$maxb" ]] && ver_gt "$vb" "$maxb" && return 0
  return 1
}

# Печатает "CVE|severity" для каждой уязвимости, которой подвержена версия
vuln_list() {
  local v="$1" cve sev ranges fixed
  [[ -z "$v" || "$v" == "unknown" ]] && return 0
  while IFS='|' read -r cve sev ranges fixed; do
    [[ -z "$cve" || "$cve" == \#* ]] && continue
    in_range "$v" "$ranges" || continue
    branch_is_fixed "$v" "$fixed" && continue
    echo "$cve|$sev"
  done <<< "$CVE_DB"
}

sev_rank() {
  case "$1" in
    critical) echo 4 ;; major) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;;
  esac
}

# Есть ли среди уязвимостей версии хоть одна >= порога
# has_severity_at_least "<список CVE|sev>" <порог>
has_severity_at_least() {
  local list="$1" threshold="$2" sev thr sr
  thr="$(sev_rank "$threshold")"
  while IFS='|' read -r _ sev; do
    [[ -z "$sev" ]] && continue
    sr="$(sev_rank "$sev")"
    [[ $sr -ge $thr ]] && return 0
  done <<< "$list"
  return 1
}

# Минимальная безопасная версия для выбранной ветки
target_version() {
  local branch_pref="$1" best="" cve sev ranges fixed item
  local -a items
  while IFS='|' read -r cve sev ranges fixed; do
    [[ -z "$cve" || "$cve" == \#* ]] && continue
    read -r -a items <<< "${fixed//,/ }"
    for item in "${items[@]:-}"; do
      [[ -z "$item" || "$item" == "none" ]] && continue
      if [[ "$branch_pref" == "mainline" ]]; then
        [[ "$(ver_branch "$item")" == "1.31" ]] || continue
      else
        [[ "$(ver_branch "$item")" == "1.30" ]] || continue
      fi
      if [[ -z "$best" ]] || ver_gt "$item" "$best"; then best="$item"; fi
    done
  done <<< "$CVE_DB"
  if [[ -z "$best" ]]; then
    [[ "$branch_pref" == "mainline" ]] && best="$TARGET_MAINLINE" || best="$TARGET_STABLE"
  fi
  echo "$best"
}

# ============================================================================
# ОНЛАЙН-ОБНОВЛЕНИЕ БАЗЫ CVE
# ============================================================================

refresh_cve_db() {
  command -v curl >/dev/null 2>&1 || return 1
  local html parsed n
  html="$(curl -fsSL --max-time 20 "$ADVISORY_URL" 2>/dev/null)" || return 1
  [[ -z "$html" ]] && return 1

  parsed="$(printf '%s\n' "$html" \
    | sed -e 's/<[Bb][Rr][^>]*>/\n/g' -e 's/<[^>]*>/ /g' \
          -e 's/&amp;/\&/g' -e 's/&nbsp;/ /g' \
    | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' \
    | awk '
      {
        if (match($0, /CVE-[0-9]+-[0-9]+/)) cve = substr($0, RSTART, RLENGTH)
        if ($0 ~ /^Severity:/) { sev = $2; gsub(/[^a-zA-Z]/, "", sev); sev = tolower(sev) }
        if ($0 ~ /^Not vulnerable:/) { nv = $0; sub(/^Not vulnerable:[ ]*/, "", nv) }
        if ($0 ~ /^Vulnerable:/) {
          vr = $0; sub(/^Vulnerable:[ ]*/, "", vr)
          if (cve != "" && nv != "" && nv !~ /none/ && vr !~ /Windows/ && vr !~ /^all/) {
            gsub(/\+/, "", nv); gsub(/[ ]/, "", nv); gsub(/[ ]/, "", vr)
            if (sev == "") sev = "medium"
            print cve "|" sev "|" vr "|" nv
          }
          cve = ""; sev = ""; nv = ""
        }
      }')"

  n="$(printf '%s\n' "$parsed" | grep -c '^CVE-' || true)"
  [[ "${n:-0}" -lt 10 ]] && return 1

  # NGINX Rift на nginx.org помечен как medium, но у него CVSS 9.2 и публичный PoC
  parsed="$(printf '%s\n' "$parsed" | sed 's/^CVE-2026-42945|[a-z]*|/CVE-2026-42945|critical|/')"
  CVE_DB="$parsed"
  return 0
}

# ============================================================================
# PHASE 1 — PRE-FLIGHT
# ============================================================================

OS_ID="unknown"; OS_LIKE=""; OS_CODENAME=""; OS_VERSION_ID=""; OS_PRETTY=""
PKG_FAMILY="unknown"; PKG_CMD=""
REPO_DISTRO=""; REPO_CODENAME=""

detect_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
    OS_VERSION_ID="${VERSION_ID:-}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_FAMILY="deb"; PKG_CMD="apt-get"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_FAMILY="rpm"; PKG_CMD="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_FAMILY="rpm"; PKG_CMD="yum"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_FAMILY="zypper"; PKG_CMD="zypper"
  elif command -v apk >/dev/null 2>&1; then
    PKG_FAMILY="apk"; PKG_CMD="apk"
  fi
}

debian_codename_from_version() {
  local maj
  maj="$(cut -d. -f1 /etc/debian_version 2>/dev/null | tr -cd '0-9')"
  case "$maj" in
    10) echo bullseye ;;  11) echo bullseye ;; 12) echo bookworm ;;
    13) echo trixie ;;    14) echo forky ;;    *) echo "" ;;
  esac
}

ubuntu_codename_from_version() {
  case "${OS_VERSION_ID:-}" in
    20.04) echo focal ;;   22.04) echo jammy ;;    24.04) echo noble ;;
    24.10) echo oracular ;; 25.04) echo plucky ;;  25.10) echo questing ;;
    26.04) echo resolute ;; *) echo "" ;;
  esac
}

# Подбираем ПРОВЕРЕННУЮ пару (distro, codename) для репозитория nginx.org.
# Именно тут ломались все прошлые версии: репозиторий прописывался вслепую,
# apt update падал, а скрипт ехал дальше.
probe_nginx_org_repo() {
  local seg="packages"
  [[ "$NGINX_TRACK" == "mainline" ]] && seg="packages/mainline"
  local d c url
  local -a cands=()

  case "$PKG_FAMILY" in
    deb)
      if [[ "$OS_ID" == "ubuntu" || "$OS_LIKE" == *ubuntu* ]]; then
        [[ -n "$OS_CODENAME" ]] && cands+=("ubuntu:$OS_CODENAME")
        c="$(ubuntu_codename_from_version)"; [[ -n "$c" ]] && cands+=("ubuntu:$c")
      fi
      if [[ "$OS_ID" == "debian" || "$OS_LIKE" == *debian* ]]; then
        [[ -n "$OS_CODENAME" ]] && cands+=("debian:$OS_CODENAME")
        c="$(debian_codename_from_version)"; [[ -n "$c" ]] && cands+=("debian:$c")
      fi
      for item in "${cands[@]:-}"; do
        [[ -z "$item" ]] && continue
        d="${item%%:*}"; c="${item##*:}"
        url="http://nginx.org/${seg}/${d}/dists/${c}/Release"
        if curl -fsI --max-time 12 "$url" >/dev/null 2>&1; then
          REPO_DISTRO="$d"; REPO_CODENAME="$c"; return 0
        fi
      done
      ;;
    rpm)
      local rel
      rel="$(rpm --eval '%{rhel}' 2>/dev/null | tr -cd '0-9')"
      [[ -z "$rel" ]] && rel="$(echo "${OS_VERSION_ID:-}" | cut -d. -f1 | tr -cd '0-9')"
      [[ -z "$rel" ]] && return 1
      local seg2=""
      [[ "$NGINX_TRACK" == "mainline" ]] && seg2="mainline/"
      local arch; arch="$(uname -m)"
      url="http://nginx.org/packages/${seg2}centos/${rel}/${arch}/repodata/repomd.xml"
      if curl -fsI --max-time 12 "$url" >/dev/null 2>&1; then
        REPO_DISTRO="centos"; REPO_CODENAME="$rel"; return 0
      fi
      ;;
  esac
  return 1
}

ensure_tool() {
  local t="$1" pkgs="$2"
  command -v "$t" >/dev/null 2>&1 && return 0
  $DRY_RUN && { warn "нет '$t' — в боевом режиме был бы доустановлен"; return 1; }
  log "доустанавливаю зависимость: $t"
  # shellcheck disable=SC2086
  case "$PKG_FAMILY" in
    deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs </dev/null >/dev/null 2>&1 ;;
    rpm) $PKG_CMD install -y -q $pkgs >/dev/null 2>&1 ;;
    apk) apk add --no-cache $pkgs >/dev/null 2>&1 ;;
    zypper) zypper -n install $pkgs >/dev/null 2>&1 ;;
  esac
  command -v "$t" >/dev/null 2>&1
}

# ============================================================================
# ИНВЕНТАРИЗАЦИЯ СИСТЕМНОГО NGINX
# ============================================================================

HAS_SYSTEM_NGINX=false
SYS_VERSION="unknown"
SYS_BIN=""
SYS_PKG=""
SYS_PKGVER=""
SYS_FROM_SOURCE=false
SYS_FROM_NGINXORG=false
SYS_CONF=""
SYS_PREFIX="/etc/nginx"
SYS_IS_OPENRESTY=false
SYS_PATCHED_BY_DISTRO=false
SYS_VULNS=""

nginx_raw_version() {
  # openresty печатает "openresty/1.27.1.2", nginx — "nginx version: nginx/1.30.4"
  local out
  out="$("$@" -v 2>&1)" || true
  printf '%s' "$out"
}

extract_version() {
  printf '%s' "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

inventory_system() {
  command -v nginx >/dev/null 2>&1 || return 0
  HAS_SYSTEM_NGINX=true
  SYS_BIN="$(command -v nginx)"

  local raw
  raw="$(nginx_raw_version nginx)"
  printf '%s' "$raw" | grep -qi 'openresty' && SYS_IS_OPENRESTY=true
  SYS_VERSION="$(extract_version "$raw")"
  [[ -z "$SYS_VERSION" ]] && SYS_VERSION="unknown"

  SYS_CONF="$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's/^--conf-path=//p' | head -n1)"
  [[ -z "$SYS_CONF" ]] && SYS_CONF="/etc/nginx/nginx.conf"
  SYS_PREFIX="$(dirname "$SYS_CONF")"

  local real
  real="$(readlink -f "$SYS_BIN" 2>/dev/null || echo "$SYS_BIN")"
  case "$PKG_FAMILY" in
    deb)
      SYS_PKG="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
      [[ -n "$SYS_PKG" ]] && SYS_PKGVER="$(dpkg-query -W -f='${Version}' "$SYS_PKG" 2>/dev/null || true)"
      if [[ -n "$SYS_PKG" ]] && dpkg -s "$SYS_PKG" 2>/dev/null | grep -qiE 'Maintainer:.*nginx\.(com|org)'; then
        SYS_FROM_NGINXORG=true
      fi
      ;;
    rpm)
      SYS_PKG="$(rpm -qf --qf '%{NAME}\n' "$real" 2>/dev/null | head -n1)"
      [[ -n "$SYS_PKG" ]] && SYS_PKGVER="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$SYS_PKG" 2>/dev/null || true)"
      if [[ -n "$SYS_PKG" ]] && rpm -qi "$SYS_PKG" 2>/dev/null | grep -qiE 'nginx\.(com|org)'; then
        SYS_FROM_NGINXORG=true
      fi
      ;;
    apk)
      SYS_PKG="$(apk info -W "$real" 2>/dev/null | awk 'NR==1{print $NF}')"
      ;;
  esac
  [[ -z "$SYS_PKG" ]] && SYS_FROM_SOURCE=true
}

# Какие CVE закрыты бэкпортами дистрибутива — берём из changelog установленного пакета.
# Это ключевой момент: Ubuntu 24.04 держит nginx 1.24.0, но с пропатченным
# ngx_http_rewrite_module. По одному лишь `nginx -v` он выглядит уязвимым.
# Список отозванных дистрибутивом патчей. Передаётся через файл, а не переменную:
# open_cves вызывается как "$(open_cves ...)", то есть в субшелле.
NGXUP_REVERTED_FILE="${NGXUP_REVERTED_FILE:-/tmp/.ngxup-reverted.$$}"

# Сырой changelog установленного пакета. Стримом, без $( ) — changelog бывает
# бинарно грязным (NUL, последовательности \x), а подстановка их калечит.
changelog_raw() {
  case "$PKG_FAMILY" in
    deb)
      local d f
      for d in "$SYS_PKG" nginx nginx-common nginx-core nginx-full nginx-light nginx-extras; do
        [[ -z "$d" ]] && continue
        for f in "/usr/share/doc/$d/changelog.Debian.gz" "/usr/share/doc/$d/changelog.gz"; do
          [[ -f "$f" ]] && zcat "$f" 2>/dev/null
        done
      done
      ;;
    rpm) rpm -q --changelog "${SYS_PKG:-nginx}" 2>/dev/null ;;
    apk) apk info -a "${SYS_PKG:-nginx}" 2>/dev/null ;;
  esac
  return 0
}

# Классификатор changelog целиком на awk: строковые эскейпы bash сюда не лезут.
#
# Дистрибутивы регулярно выкатывают фикс и следующей ревизией отключают его:
#   1.24.0-2ubuntu7.14  SECURITY UPDATE: ... CVE-2026-42533-1.patch
#   1.24.0-2ubuntu7.15  SECURITY REGRESSION: CVE-2026-42533-*.patch: Disabled for now.
# Простой grep по CVE-ID прочитает вторую строку как «закрыто» — наоборот.
# Идём по записям сверху вниз (changelog отсортирован от новых к старым),
# первое решение по каждому CVE окончательное: это заодно даёт «отключили, потом вернули».
CHANGELOG_AWK='
function decide(  cve, ctx, isrev) {
  if (nl == 0) return
  isreg = 0
  for (i = 1; i <= nl; i++)
    if (tolower(L[i]) ~ /security regression|regression update/) isreg = 1
  for (cve in CTX) delete CTX[cve]
  for (i = 1; i <= nl; i++) {
    t = L[i]
    while (match(t, /CVE-[0-9][0-9][0-9][0-9]-[0-9]+/)) {
      cve = toupper(substr(t, RSTART, RLENGTH))
      t = substr(t, RSTART + RLENGTH)
      CTX[cve] = CTX[cve] " " tolower(L[i])
    }
  }
  for (cve in CTX) {
    if (cve in D) continue
    ctx = CTX[cve]
    isrev = 0
    # откат засчитываем только внутри записи-регрессии и только если отключённым
    # назван сам патч. "disabled duplicate atoms in Mp4" описывает, что делает
    # патч; "Dropped: ... replaced with upstream" значит, что фикс приехал с версией.
    if (isreg && ctx ~ /disabl|revert|backed out|dropped|removed|no longer/ &&
        ctx !~ /replaced with upstream|fixed in [0-9]|superseded/) isrev = 1
    D[cve] = isrev ? "R" : "F"
  }
  nl = 0
}
/^[a-zA-Z0-9][a-zA-Z0-9.+-]* \(/ { decide(); L[++nl] = $0; next }
/^\* [A-Z][a-z][a-z] [A-Z][a-z][a-z] / { decide(); L[++nl] = $0; next }
{ L[++nl] = $0 }
END { decide(); for (c in D) print D[c] " " c }
'

distro_fixed_cves() {
  changelog_raw | tr -d '\000' | awk "$CHANGELOG_AWK" | sort -u
}

# Итоговый вердикт: список НЕзакрытых CVE (с учётом бэкпортов)
open_cves() {
  local v="$1" both fixed reverted line cve sev
  : > "$NGXUP_REVERTED_FILE" 2>/dev/null || true
  if $SYS_FROM_NGINXORG || $SYS_FROM_SOURCE || [[ "$PKG_FAMILY" == "unknown" ]]; then
    vuln_list "$v"
    return 0
  fi
  both="$(distro_fixed_cves)"
  fixed="$(grep '^F ' <<< "$both" | cut -c3- || true)"
  reverted="$(grep '^R ' <<< "$both" | cut -c3- || true)"
  printf '%s' "$reverted" > "$NGXUP_REVERTED_FILE" 2>/dev/null || true
  if [[ -z "$fixed" && -z "$reverted" ]]; then
    vuln_list "$v"
    return 0
  fi
  while IFS='|' read -r cve sev; do
    [[ -z "$cve" ]] && continue
    # Отозванный дистрибутивом патч = дыра открыта, даже если CVE упомянут в changelog
    if [[ -n "$reverted" ]] && grep -qxF "$cve" <<< "$reverted"; then
      printf '%s|%s\n' "$cve" "$sev"
      continue
    fi
    grep -qxF "$cve" <<< "$fixed" && continue
    printf '%s|%s\n' "$cve" "$sev"
  done < <(vuln_list "$v")
}

# ============================================================================
# BACKUP / СЛЕПОК СОСТОЯНИЯ / ОТКАТ
# ============================================================================

BACKUP_DIR=""
LISTENERS_BEFORE=""
SMOKE_BEFORE=""
NGINX_WAS_RUNNING=false

nginx_listeners() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltnp 2>/dev/null | awk '/nginx/ {print $4}' | sort -u
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltnp 2>/dev/null | awk '/nginx/ {print $4}' | sort -u
  fi
}

# Порт из "0.0.0.0:443" / "[::]:443" / "127.0.0.1:8443"
_lp_port() { printf '%s' "${1##*:}"; }
_lp_host() {
  local a="${1%:*}"
  case "$a" in
    '*'|'0.0.0.0'|'[::]'|'[::1]'|'') echo "127.0.0.1" ;;
    \[*\]) echo "${a}" ;;
    *) echo "$a" ;;
  esac
}

smoke_probe() {
  command -v curl >/dev/null 2>&1 || return 0
  local l host port code
  while read -r l; do
    [[ -z "$l" ]] && continue
    host="$(_lp_host "$l")"; port="$(_lp_port "$l")"
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "http://${host}:${port}/" 2>/dev/null || echo 000)"
    if [[ "$code" == "000" ]]; then
      code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://${host}:${port}/" 2>/dev/null || echo 000)"
    fi
    echo "${l} ${code}"
  done <<< "$(nginx_listeners)"
}

make_backup() {
  BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR" || { BACKUP_DIR="$(mktemp -d)"; }
  if [[ -d "$SYS_PREFIX" ]]; then
    tar czf "$BACKUP_DIR/etc-nginx.tgz" -C / "${SYS_PREFIX#/}" 2>/dev/null || true
    mkdir -p "$BACKUP_DIR/tree"
    cp -a "$SYS_PREFIX/." "$BACKUP_DIR/tree/" 2>/dev/null || true
  fi
  case "$PKG_FAMILY" in
    deb) dpkg -l 'nginx*' > "$BACKUP_DIR/packages-before.txt" 2>/dev/null || true ;;
    rpm) rpm -qa 'nginx*' > "$BACKUP_DIR/packages-before.txt" 2>/dev/null || true ;;
  esac
  nginx -V > "$BACKUP_DIR/nginx-V.txt" 2>&1 || true
  LISTENERS_BEFORE="$(nginx_listeners)"
  SMOKE_BEFORE="$(smoke_probe)"
  if pgrep -x nginx >/dev/null 2>&1 || [[ -n "$LISTENERS_BEFORE" ]]; then
    NGINX_WAS_RUNNING=true
  else
    log "nginx сейчас не запущен — после изменений ограничусь проверкой nginx -t"
  fi
  printf '%s\n' "$LISTENERS_BEFORE" > "$BACKUP_DIR/listeners-before.txt"
  printf '%s\n' "$SMOKE_BEFORE"     > "$BACKUP_DIR/smoke-before.txt"
  log "Бэкап: $BACKUP_DIR"
}

restore_config() {
  [[ -z "$BACKUP_DIR" || ! -f "$BACKUP_DIR/etc-nginx.tgz" ]] && return 1
  warn "Восстанавливаю конфигурацию из $BACKUP_DIR/etc-nginx.tgz"
  tar xzf "$BACKUP_DIR/etc-nginx.tgz" -C / 2>/dev/null || return 1
  return 0
}

restart_nginx() {
  if command -v systemctl >/dev/null 2>&1 && systemctl cat nginx >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart nginx
  elif command -v service >/dev/null 2>&1; then
    service nginx restart
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service nginx restart
  else
    nginx -s quit 2>/dev/null || true
    sleep 1
    nginx
  fi
}

nginx_test() { nginx -t >/dev/null 2>&1; }
nginx_test_verbose() { nginx -t 2>&1 | sed 's/^/     /'; }

# ============================================================================
# АВТОРЕМОНТ КОНФИГА
# Здесь чинится ровно то, из-за чего у людей после апгрейда пропадали сайты
# ============================================================================

CONF_FIXES=()
CONF_FIXES_N=0
conf_fixed() { CONF_FIXES+=("$1"); CONF_FIXES_N=$((CONF_FIXES_N + 1)); }

# Вставить директиву перед закрывающей скобкой блока http {}
insert_into_http() {
  local file="$1" line="$2" tmp
  tmp="$(mktemp)"
  awk -v ins="$line" '
    {
      c = $0; sub(/#.*/, "", c)
      if (!inhttp && c ~ /(^|[^A-Za-z_])http[[:space:]]*\{/) { inhttp = 1; depth = 0 }
      if (inhttp && !done) {
        o = gsub(/\{/, "{", c); cl = gsub(/\}/, "}", c)
        nd = depth + o - cl
        if (nd == 0 && depth > 0) { print ins; done = 1 }
        depth = nd
      }
      print
    }
    END { if (!done) exit 3 }
  ' "$file" > "$tmp"
  local rc=$?
  if [[ $rc -ne 0 ]]; then rm -f "$tmp"; return 1; fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
  return 0
}

# Ссылается ли конфиг (с учётом include) на каталог
conf_includes_dir() {
  local dir="${1%/}"
  # nginx -T показывает РЕАЛЬНО загруженные файлы — это авторитетнее grep по include
  local dump
  if dump="$(nginx -T 2>/dev/null)" && [[ -n "$dump" ]]; then
    grep -q "^# configuration file ${dir}/" <<< "$dump" && return 0
    grep -qE "^[[:space:]]*include[[:space:]]+[\"']?${dir}/" <<< "$dump" && return 0
    return 1
  fi
  grep -rhE "^[[:space:]]*include[[:space:]]+[\"']?${dir}/" "$SYS_PREFIX" 2>/dev/null | grep -q . && return 0
  return 1
}

repair_include_dirs() {
  local d changed=0
  for d in "$SYS_PREFIX/sites-enabled" "$SYS_PREFIX/conf.d"; do
    [[ -d "$d" ]] || continue
    # каталог пустой — включать нечего
    find "$d" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | head -1 | grep -q . || continue
    conf_includes_dir "$d" && continue

    local inc
    if [[ "$d" == *conf.d ]]; then inc="    include ${d}/*.conf;"; else inc="    include ${d}/*;"; fi
    warn "в $SYS_CONF нет include для ${d} — сайты бы не подхватились. Вставляю."
    cp -a "$SYS_CONF" "$SYS_CONF.ngxup-bak" 2>/dev/null || true
    if insert_into_http "$SYS_CONF" "$inc"; then
      if nginx_test; then
        ok "добавлено: ${inc# }"
        conf_fixed "include ${d}"
        changed=1
      else
        err "include добавлен, но конфиг не проходит nginx -t — значит ошибка В САМИХ САЙТАХ:"
        nginx_test_verbose
        cp -a "$SYS_CONF.ngxup-bak" "$SYS_CONF"
        err "откатил вставку, чтобы не уронить nginx. Почини ошибку выше и запусти скрипт снова."
        manual "сайты из ${d} не обслуживаются: после подключения include падает nginx -t (см. ошибку в логе $LOG_FILE)"
      fi
    else
      warn "не нашёл блок http {} в $SYS_CONF — вставь вручную: ${inc# }"
      manual "вставить '${inc# }' в http{} файла $SYS_CONF"
    fi
    rm -f "$SYS_CONF.ngxup-bak"
  done
  [[ $changed -eq 1 ]] && return 0
  return 0
}

repair_conf_user() {
  local u
  u="$(grep -hE '^[[:space:]]*user[[:space:]]+' "$SYS_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' \
       | head -n1 | awk '{print $2}' | tr -d ';')"
  [[ -z "$u" ]] && return 0
  id -u "$u" >/dev/null 2>&1 && return 0

  warn "в конфиге указан пользователь '$u', которого нет в системе — создаю"
  if useradd --system --no-create-home --shell /usr/sbin/nologin "$u" >/dev/null 2>&1 \
     || adduser --system --no-create-home --group "$u" >/dev/null 2>&1; then
    local p
    for p in /var/cache/nginx /var/lib/nginx /var/log/nginx; do
      [[ -d "$p" ]] && chown -R "$u" "$p" 2>/dev/null || true
    done
    ok "создан системный пользователь '$u'"
    conf_fixed "создан пользователь $u"
  else
    manual "создать системного пользователя '$u' (указан в $SYS_CONF)"
  fi
}

# Отключаем ТОЛЬКО те файлы modules-enabled, на которые ругается сам nginx.
# Раньше здесь резолвился путь load_module относительно /etc/nginx — неверно:
# nginx резолвит его относительно --modules-path (обычно /usr/lib/nginx/modules).
repair_modules() {
  [[ -d "$SYS_PREFIX/modules-enabled" ]] || return 0
  nginx_test && return 0

  local out file tries=0
  while [[ $tries -lt 10 ]]; do
    tries=$((tries + 1))
    out="$(nginx -t 2>&1)"
    nginx_test && break
    grep -qiE 'dlopen|load_module|module .* is not binary compatible' <<< "$out" || break
    file="$(grep -oE 'in [^ ]*modules-enabled/[^:]+' <<< "$out" | head -n1 | sed 's/^in //')"
    [[ -z "$file" || ! -f "$file" ]] && break
    warn "nginx не может загрузить модуль из $(basename "$file") — отключаю файл"
    mv "$file" "$file.disabled-by-nginx-updater"
    conf_fixed "отключён $(basename "$file") (модуль не грузится)"
  done
  return 0
}

# listen ... http2  →  http2 on;   (deprecated с nginx 1.25.1)
# Конвертируем только там, где ВСЕ listen в server{} идут с ssl,
# иначе http2 on включил бы h2c на 80-м порту.
HTTP2_AWK='
{ L[NR] = $0 }
END {
  n = NR; sstart = 0; depth = 0
  for (i = 1; i <= n; i++) {
    c = L[i]; sub(/#.*/, "", c)
    if (!sstart && c ~ /(^|[^A-Za-z_])server[ \t]*\{/) { sstart = i; depth = 0 }
    if (sstart) {
      depth += gsub(/\{/, "{", c) - gsub(/\}/, "}", c)
      if (depth <= 0 && i > sstart) { conv(sstart, i); sstart = 0 }
    }
  }
  for (i = 1; i <= n; i++) print (i in OUT) ? OUT[i] : L[i]
}
function conv(a, b,   j, allssl, has, ind, nl, emitted, c2) {
  allssl = 1; has = 0; emitted = 0
  for (j = a; j <= b; j++) {
    c2 = L[j]; sub(/#.*/, "", c2)
    if (c2 ~ /(^|[ \t])listen[ \t]/) {
      if (c2 ~ /[ \t]http2([ \t]|;|$)/) has = 1
      if (c2 !~ /[ \t]ssl([ \t]|;|$)/)  allssl = 0
    }
  }
  if (!has || !allssl) return
  for (j = a; j <= b; j++) {
    c2 = L[j]; sub(/#.*/, "", c2)
    if (c2 ~ /(^|[ \t])listen[ \t]/ && c2 ~ /[ \t]http2([ \t]|;|$)/) {
      ind = L[j]; sub(/[^ \t].*$/, "", ind)
      nl = L[j]
      gsub(/[ \t]+http2[ \t]*;/, ";", nl)
      gsub(/[ \t]+http2[ \t]+/, " ", nl)
      if (!emitted) { OUT[j] = nl "\n" ind "http2 on;"; emitted = 1 }
      else OUT[j] = nl
    }
  }
}
'

repair_http2() {
  $FIX_HTTP2 || return 0
  ver_ge "$SYS_VERSION" "1.25.1" || return 0

  local files f tmp touched=0
  files="$(grep -rlE '^[^#]*listen[^;]*[[:space:]]http2([[:space:]]|;)' "$SYS_PREFIX" 2>/dev/null || true)"
  [[ -z "$files" ]] && return 0

  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    tmp="$(mktemp)"
    if ! awk "$HTTP2_AWK" "$f" > "$tmp" 2>/dev/null; then rm -f "$tmp"; continue; fi
    if [[ -s "$tmp" ]] && ! cmp -s "$f" "$tmp"; then
      cp -a "$f" "$f.ngxup-bak"
      cat "$tmp" > "$f"
      if nginx_test; then
        ok "$(basename "$f"): listen ... http2 → http2 on;"
        touched=1
        rm -f "$f.ngxup-bak"
      else
        warn "$(basename "$f"): миграция http2 не прошла nginx -t — откатил, файл не тронут"
        cp -a "$f.ngxup-bak" "$f"; rm -f "$f.ngxup-bak"
      fi
    fi
    rm -f "$tmp"
  done <<< "$files"

  [[ $touched -eq 1 ]] && conf_fixed "мигрирован deprecated listen ... http2"
  return 0
}

# Конфликт stock default.conf от nginx.org с восстановленными сайтами
disable_stock_default() {
  local f="$SYS_PREFIX/conf.d/default.conf"
  [[ -f "$f" ]] || return 0
  # трогаем только нетронутый stock-файл от nginx.org
  grep -q 'server_name[[:space:]]*localhost' "$f" 2>/dev/null || return 0
  grep -q '/usr/share/nginx/html' "$f" 2>/dev/null || return 0
  [[ -d "$SYS_PREFIX/sites-enabled" ]] || return 0
  find "$SYS_PREFIX/sites-enabled" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) 2>/dev/null \
    | head -1 | grep -q . || return 0
  warn "stock conf.d/default.conf конфликтует с твоим default_server — отключаю"
  mv "$f" "$f.disabled-by-nginx-updater"
  conf_fixed "отключён stock conf.d/default.conf"
}

repair_config() {
  $FIX_CONFIG || return 0
  $HAS_SYSTEM_NGINX || return 0
  header "Ремонт конфигурации"

  # nginx.conf унесло обновлением пакета — поднимаем из .dpkg-*/.rpm*
  if [[ ! -f "$SYS_CONF" ]]; then
    local cand
    for cand in "$SYS_CONF.dpkg-dist" "$SYS_CONF.rpmnew" "$SYS_CONF.dpkg-old" "$SYS_CONF.rpmsave"; do
      if [[ -f "$cand" ]]; then
        warn "$SYS_CONF отсутствует, беру $cand"
        cp -a "$cand" "$SYS_CONF"
        conf_fixed "восстановлен $SYS_CONF из $(basename "$cand")"
        break
      fi
    done
  fi
  [[ -f "$SYS_CONF" ]] || { manual "нет $SYS_CONF"; return 1; }

  local manual_before=$NEEDS_MANUAL_N
  repair_conf_user
  repair_modules
  disable_stock_default
  repair_include_dirs
  repair_http2

  if [[ $CONF_FIXES_N -eq 0 && $NEEDS_MANUAL_N -eq $manual_before ]]; then
    ok "конфигурация в порядке, править нечего"
  fi
  return 0
}

# ============================================================================
# PHASE — СИСТЕМНЫЙ NGINX
# ============================================================================

installed_nginx_debs() {
  dpkg-query -W -f='${Package} ${Status}\n' 'nginx*' 2>/dev/null \
    | awk '$2=="install"{print $1}'
}

has_nginx_org_repo() {
  grep -rhsE '^[[:space:]]*deb[[:space:]].*nginx\.org' \
       /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -q . && return 0
  grep -rlsE '^[[:space:]]*URIs:.*nginx\.org' \
       /etc/apt/sources.list.d/ 2>/dev/null | grep -q . && return 0
  return 1
}

apt_candidate() {
  LC_ALL=C apt-cache policy nginx 2>/dev/null | awk '/Candidate:/{print $2}'
}

upgrade_via_distro() {
  log "Пробую штатный репозиторий дистрибутива (безопасный путь, конфиг не трогается)"
  case "$PKG_FAMILY" in
    deb)
      local pkgs
      pkgs="$(installed_nginx_debs | tr '\n' ' ')"
      [[ -z "$pkgs" ]] && pkgs="nginx"
      apt-get update -qq </dev/null >/dev/null 2>&1 || warn "apt-get update отработал с ошибками"
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
        -o Dpkg::Options::=--force-confold \
        -o Dpkg::Options::=--force-confdef \
        $pkgs </dev/null 2>&1 | sed 's/^/     /'
      ;;
    rpm)
      $PKG_CMD -y -q update nginx 2>&1 | sed 's/^/     /'
      ;;
    apk)
      apk update >/dev/null 2>&1; apk upgrade nginx 2>&1 | sed 's/^/     /'
      ;;
    zypper)
      zypper -n refresh >/dev/null 2>&1; zypper -n update nginx 2>&1 | sed 's/^/     /'
      ;;
    *) return 1 ;;
  esac
  return 0
}

add_nginx_org_repo_deb() {
  ensure_tool curl "curl ca-certificates" || { manual "нужен curl"; return 1; }
  ensure_tool gpg  "gnupg" || { manual "нужен gnupg"; return 1; }

  local seg="packages"
  [[ "$NGINX_TRACK" == "mainline" ]] && seg="packages/mainline"

  curl -fsSL --max-time 20 https://nginx.org/keys/nginx_signing.key \
    | gpg --dearmor --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null \
    || { err "не смог получить ключ nginx.org"; return 1; }
  chmod 0644 /usr/share/keyrings/nginx-archive-keyring.gpg

  printf 'deb [arch=%s signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/%s/%s %s nginx\n' \
    "$(dpkg --print-architecture)" "$seg" "$REPO_DISTRO" "$REPO_CODENAME" \
    > /etc/apt/sources.list.d/nginx.list

  cat > /etc/apt/preferences.d/99-nginx-org.pref <<'__PREF__'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 900
__PREF__

  apt-get update -qq </dev/null >/dev/null 2>&1 || {
    err "apt-get update упал после подключения nginx.org"
    rm -f /etc/apt/sources.list.d/nginx.list /etc/apt/preferences.d/99-nginx-org.pref
    apt-get update -qq </dev/null >/dev/null 2>&1 || true
    return 1
  }
  ok "репозиторий nginx.org подключён: $REPO_DISTRO/$REPO_CODENAME ($NGINX_TRACK)"
  return 0
}

add_nginx_org_repo_rpm() {
  local seg=""
  [[ "$NGINX_TRACK" == "mainline" ]] && seg="mainline/"
  cat > /etc/yum.repos.d/nginx.repo <<__REPO__
[nginx-${NGINX_TRACK}]
name=nginx ${NGINX_TRACK} repo
baseurl=http://nginx.org/packages/${seg}centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
__REPO__
  ok "репозиторий nginx.org подключён (centos/$REPO_CODENAME, $NGINX_TRACK)"
  return 0
}

# Восстановить всё, что снёс менеджер пакетов при смене происхождения nginx
restore_user_configs() {
  [[ -d "$BACKUP_DIR/tree" ]] || return 0
  mkdir -p "$SYS_PREFIX"
  # -n: не затирать то, что положил новый пакет; -a: сохранить симлинки sites-enabled
  cp -an "$BACKUP_DIR/tree/." "$SYS_PREFIX/" 2>/dev/null || true
  ok "пользовательские файлы конфигурации восстановлены на место"
}

# Стратегия nginx.conf после миграции: сначала пробуем СТАРЫЙ (в нём вся тюнинговка),
# и только если он не заводится с новым бинарём — оставляем дефолтный от nginx.org
reconcile_nginx_conf() {
  local old
  old="$BACKUP_DIR/tree/$(basename "$SYS_CONF")"
  [[ -f "$old" ]] || return 0
  cmp -s "$old" "$SYS_CONF" && return 0

  log "nginx.conf заменён пакетом — пробую вернуть твой"
  cp -a "$SYS_CONF" "$SYS_PREFIX/nginx.conf.nginx-org-default" 2>/dev/null || true
  cp -a "$old" "$SYS_CONF"
  repair_conf_user
  repair_modules
  if nginx_test; then
    ok "твой nginx.conf принят новым бинарём (дефолтный сохранён как nginx.conf.nginx-org-default)"
    conf_fixed "сохранён исходный nginx.conf"
  else
    warn "твой nginx.conf не проходит nginx -t на новой версии:"
    nginx_test_verbose
    warn "возвращаю дефолтный nginx.conf от nginx.org и достраиваю include'ы"
    cp -a "$SYS_PREFIX/nginx.conf.nginx-org-default" "$SYS_CONF"
    # перенесём хотя бы user и worker_processes
    local u wp
    u="$(grep -hE '^[[:space:]]*user[[:space:]]+' "$old" 2>/dev/null | head -1 || true)"
    wp="$(grep -hE '^[[:space:]]*worker_processes[[:space:]]+' "$old" 2>/dev/null | head -1 || true)"
    [[ -n "$u"  ]] && sed -i "0,/^[[:space:]]*user[[:space:]].*/s||${u}|" "$SYS_CONF"
    [[ -n "$wp" ]] && sed -i "0,/^[[:space:]]*worker_processes[[:space:]].*/s||${wp}|" "$SYS_CONF"
    conf_fixed "nginx.conf от nginx.org + перенос user/worker_processes"
    manual "сверь $SYS_CONF со своим бэкапом: $BACKUP_DIR/tree/$(basename "$SYS_CONF")"
  fi
}

migrate_to_nginx_org() {
  header "Миграция на репозиторий nginx.org"
  warn "дистрибутив не может закрыть уязвимость — перехожу на пакеты nginx.org"
  note "вся конфигурация уже в бэкапе, после установки она восстанавливается автоматически"

  if ! probe_nginx_org_repo; then
    err "nginx.org не публикует пакеты для $OS_PRETTY ($OS_ID/$OS_CODENAME)"
    manual "собрать nginx $(target_version "$NGINX_TRACK") из исходников (флаги: $BACKUP_DIR/nginx-V.txt)"
    return 1
  fi

  case "$PKG_FAMILY" in
    deb)
      add_nginx_org_repo_deb || return 1
      local cand; cand="$(apt_candidate)"
      local candv; candv="$(extract_version "$cand")"
      if [[ -z "$candv" ]] || [[ -n "$(vuln_list "$candv")" ]]; then
        err "кандидат из nginx.org ($cand) тоже не закрывает всё — прерываю миграцию"
        rm -f /etc/apt/sources.list.d/nginx.list /etc/apt/preferences.d/99-nginx-org.pref
        apt-get update -qq </dev/null >/dev/null 2>&1 || true
        manual "проверить nginx.org вручную: apt-cache policy nginx"
        return 1
      fi
      log "кандидат nginx.org: $cand"

      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::=--force-confold \
        -o Dpkg::Options::=--force-confdef \
        nginx </dev/null > "$BACKUP_DIR/apt-install.log" 2>&1 || true
      tail -n 8 "$BACKUP_DIR/apt-install.log" | sed 's/^/     /'

      if ! dpkg -s nginx 2>/dev/null | grep -qiE 'Maintainer:.*nginx\.(com|org)'; then
        warn "прямая установка не прошла (конфликт conffile с пакетом дистрибутива)"
        log "удаляю пакеты дистрибутива и ставлю заново — конфиги уже сохранены"
        local old_pkgs; old_pkgs="$(installed_nginx_debs | tr '\n' ' ')"
        # shellcheck disable=SC2086
        DEBIAN_FRONTEND=noninteractive apt-get purge -y $old_pkgs </dev/null >/dev/null 2>&1 || true
        # ВАЖНО: сначала ставим пакет, потом возвращаем конфиги. Если положить свои
        # файлы заранее, dpkg увидит их как изменённые conffile, спросит Y/I/N/O/D/Z,
        # упрётся в EOF на stdin и оставит пакет в состоянии half-configured.
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
          -o Dpkg::Options::=--force-confold \
          -o Dpkg::Options::=--force-confdef \
          nginx </dev/null > "$BACKUP_DIR/apt-reinstall.log" 2>&1 || true
        tail -n 6 "$BACKUP_DIR/apt-reinstall.log" | sed 's/^/     /'
      fi
      ;;
    rpm)
      add_nginx_org_repo_rpm || return 1
      $PKG_CMD clean all -q >/dev/null 2>&1 || true
      $PKG_CMD -y install nginx 2>&1 | sed 's/^/     /'
      ;;
    *)
      manual "автоматическая миграция для $PKG_FAMILY не поддержана"
      return 1
      ;;
  esac

  restore_user_configs
  reconcile_nginx_conf
  command -v systemctl >/dev/null 2>&1 && { systemctl daemon-reload >/dev/null 2>&1 || true; systemctl enable nginx >/dev/null 2>&1 || true; }
  return 0
}

verify_and_rollback() {
  local stage="$1"

  if ! nginx_test; then
    err "nginx -t не проходит после этапа '$stage':"
    nginx_test_verbose
    if $AUTO_ROLLBACK && restore_config; then
      if nginx_test; then
        warn "конфиг откачен, перезапускаю на старом конфиге"
        restart_nginx || true
      fi
    fi
    EXIT_CODE=1
    return 1
  fi

  if ! $NGINX_WAS_RUNNING; then
    ok "конфиг валиден. nginx не был запущен — не стартую его сам, запусти когда будешь готов"
    return 0
  fi

  log "перезапуск nginx (полный restart, не reload)"
  if ! restart_nginx; then
    err "nginx не перезапустился"
    $AUTO_ROLLBACK && restore_config && restart_nginx || true
    EXIT_CODE=1
    return 1
  fi
  sleep 2

  if command -v systemctl >/dev/null 2>&1 && systemctl cat nginx >/dev/null 2>&1; then
    if ! systemctl is-active --quiet nginx; then
      err "сервис nginx не активен после рестарта"
      systemctl status nginx --no-pager -l 2>&1 | tail -20 | sed 's/^/     /'
      if $AUTO_ROLLBACK && restore_config; then restart_nginx || true; fi
      EXIT_CODE=1
      return 1
    fi
  fi

  # Сравниваем слушающие сокеты до/после — самая частая тихая поломка
  local after missing=""
  after="$(nginx_listeners)"
  local l
  while read -r l; do
    [[ -z "$l" ]] && continue
    grep -qxF "$l" <<< "$after" || missing+="$l "
  done <<< "$LISTENERS_BEFORE"

  if [[ -n "$missing" ]]; then
    err "после апгрейда пропали слушающие сокеты: $missing"
    if $AUTO_ROLLBACK; then
      warn "откатываю конфигурацию"
      if restore_config && nginx_test && restart_nginx; then
        sleep 2
        after="$(nginx_listeners)"
        warn "конфигурация откачена. Сокеты сейчас: $(echo "$after" | tr '\n' ' ')"
        manual "апгрейд бинаря выполнен, но твой конфиг с ним не поднялся — разбери $BACKUP_DIR"
      fi
    fi
    EXIT_CODE=1
    return 1
  fi

  # Дымовой тест: порт, который отвечал раньше, должен отвечать и сейчас
  local before_line port_after dead=""
  local smoke_after; smoke_after="$(smoke_probe)"
  while read -r before_line; do
    [[ -z "$before_line" ]] && continue
    local addr code
    addr="${before_line%% *}"; code="${before_line##* }"
    [[ "$code" == "000" ]] && continue
    port_after="$(grep -F "$addr " <<< "$smoke_after" | awk '{print $2}' | head -1)"
    [[ "${port_after:-000}" == "000" ]] && dead+="$addr "
  done <<< "$SMOKE_BEFORE"

  if [[ -n "$dead" ]]; then
    err "сокеты слушают, но перестали отвечать: $dead"
    if $AUTO_ROLLBACK && restore_config && nginx_test; then
      restart_nginx || true
      warn "конфигурация откачена"
    fi
    EXIT_CODE=1
    return 1
  fi

  ok "проверка пройдена: конфиг валиден, сервис поднят, все сокеты на месте и отвечают"
  return 0
}

upgrade_system() {
  header "Системный nginx"

  if $SKIP_SYSTEM; then log "--skip-system → пропуск"; return 0; fi
  if ! $HAS_SYSTEM_NGINX; then log "системный nginx не установлен → пропуск"; return 0; fi

  if [[ "$SYS_VERSION" == "unknown" ]]; then
    err "не смог определить версию системного nginx — не рискую трогать"
    manual "определить версию вручную: nginx -v"
    return 1
  fi

  if $SYS_IS_OPENRESTY; then
    warn "это OpenResty ($SYS_VERSION) — у него свой цикл релизов, пакетный апгрейд не подходит"
    manual "обновить OpenResty вручную до сборки на nginx >= $(target_version "$NGINX_TRACK")"
    return 1
  fi

  SYS_VULNS="$(open_cves "$SYS_VERSION")"
  if [[ -z "$SYS_VULNS" ]]; then
    if $SYS_FROM_NGINXORG || $SYS_FROM_SOURCE; then
      ok "системный nginx $SYS_VERSION — все известные CVE закрыты"
    else
      ok "системный nginx $SYS_VERSION (пакет $SYS_PKGVER) — уязвимости закрыты бэкпортами дистрибутива"
      SYS_PATCHED_BY_DISTRO=true
    fi
    return 0
  fi

  warn "системный nginx $SYS_VERSION уязвим:"
  local c s
  while IFS='|' read -r c s; do [[ -n "$c" ]] && note "$c ($s)"; done <<< "$SYS_VULNS"

  # Отдельно и громко: дистрибутив выпускал фикс, потом отозвал его.
  # Обычная логика "нет новой версии в репо — значит всё в порядке" тут врёт:
  # apt upgrade не поможет, пока мейнтейнер не выпустит исправленный патч.
  DISTRO_REVERTED_CVES="$(cat "$NGXUP_REVERTED_FILE" 2>/dev/null || true)"
  if [[ -n "$DISTRO_REVERTED_CVES" ]]; then
    while read -r c; do
      [[ -z "$c" ]] && continue
      grep -q "^$c|" <<< "$SYS_VULNS" || continue
      err "$c: дистрибутив ВЫПУСТИЛ и затем ОТОЗВАЛ патч (см. changelog пакета $SYS_PKGVER)"
      note "apt upgrade это не закроет — нужен nginx.org или исправленный патч от мейнтейнера"
      manual "$c: патч дистрибутива отозван, штатное обновление не поможет"
    done <<< "$DISTRO_REVERTED_CVES"
  fi

  if $SYS_FROM_SOURCE; then
    err "nginx собран из исходников (не принадлежит ни одному пакету) — пакетный апгрейд невозможен"
    manual "пересобрать nginx $(target_version "$NGINX_TRACK") с флагами из $BACKUP_DIR/nginx-V.txt"
    return 1
  fi

  if $DRY_RUN; then
    warn "[DRY-RUN] был бы выполнен апгрейд до >= $(target_version "$NGINX_TRACK")"
    $SYS_FROM_NGINXORG && note "путь: apt/dnf install nginx из уже подключённого nginx.org" \
                       || note "путь: сначала репозиторий дистрибутива, при неуспехе — миграция на nginx.org"
    return 0
  fi

  if ! $PREFER_UPSTREAM && ! $SYS_FROM_NGINXORG; then
    upgrade_via_distro
    inventory_system
    SYS_VULNS="$(open_cves "$SYS_VERSION")"
    if [[ -z "$SYS_VULNS" ]]; then
      ok "закрыто обновлением из репозитория дистрибутива (nginx $SYS_VERSION, пакет $SYS_PKGVER)"
      acted "системный nginx обновлён из репозитория дистрибутива"
      return 0
    fi
    warn "дистрибутив не закрыл всё, осталось: $(echo "$SYS_VULNS" | cut -d'|' -f1 | tr '\n' ' ')"
  elif $SYS_FROM_NGINXORG; then
    upgrade_via_distro
    inventory_system
    SYS_VULNS="$(open_cves "$SYS_VERSION")"
    if [[ -z "$SYS_VULNS" ]]; then
      ok "обновлено из nginx.org: nginx $SYS_VERSION"
      acted "системный nginx обновлён (nginx.org)"
      return 0
    fi
  fi

  if $DISTRO_ONLY; then
    warn "--distro-only: остаюсь на пакетах дистрибутива"
    manual "дождаться обновления в дистрибутиве либо снять --distro-only"
    return 1
  fi

  if ! has_severity_at_least "$SYS_VULNS" "$MIGRATE_SEVERITY"; then
    warn "остались только уязвимости ниже порога --severity $MIGRATE_SEVERITY — на nginx.org не мигрирую"
    manual "остаточные CVE: $(echo "$SYS_VULNS" | cut -d'|' -f1 | tr '\n' ' ')"
    return 0
  fi

  migrate_to_nginx_org || return 1
  inventory_system
  SYS_VULNS="$(open_cves "$SYS_VERSION")"
  acted "системный nginx мигрирован на nginx.org → $SYS_VERSION"

  # Пакет должен быть не просто распакован, а настроен. Прерванный dpkg
  # (например, интерактивный вопрос про conffile) оставляет состояние half-configured:
  # nginx работает, а любой следующий apt падает.
  ensure_pkg_configured

  if [[ -z "$SYS_VULNS" ]]; then
    ok "после миграции: nginx $SYS_VERSION, известных открытых CVE нет"
    # пометки про отозванные дистрибутивом патчи потеряли смысл — мы ушли с них
    manual_drop "патч дистрибутива отозван"
    manual_drop "остаточные CVE"
  else
    warn "после миграции всё ещё открыто: $(echo "$SYS_VULNS" | cut -d'|' -f1 | tr '\n' ' ')"
  fi
  return 0
}

# Проверить и при необходимости починить состояние пакета после dpkg.
ensure_pkg_configured() {
  [[ "$PKG_FAMILY" == "deb" ]] || return 0
  local st
  st="$(dpkg-query -W -f='${Status}' nginx 2>/dev/null || true)"
  [[ "$st" == "install ok installed" ]] && return 0
  [[ -z "$st" ]] && return 0
  warn "пакет nginx остался в состоянии «$st» — довожу dpkg --configure -a"
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a \
    --force-confold --force-confdef </dev/null >/dev/null 2>&1 || true
  st="$(dpkg-query -W -f='${Status}' nginx 2>/dev/null || true)"
  if [[ "$st" == "install ok installed" ]]; then
    ok "состояние пакета восстановлено"
  else
    err "пакет nginx в состоянии «$st» — следующий apt упадёт"
    manual "починить пакет: dpkg --configure -a (или apt-get -f install)"
  fi
  return 0
}

# ============================================================================
# PHASE — DOCKER
# ============================================================================

HAS_DOCKER=false
DOCKER_NGINX=()
DOCKER_NGINX_N=0
COMPOSE_CMD=()

detect_docker() {
  command -v docker >/dev/null 2>&1 || return 0
  docker info >/dev/null 2>&1 || return 0
  HAS_DOCKER=true
}

dlabel() { docker inspect -f "{{ index .Config.Labels \"$2\" }}" "$1" 2>/dev/null | grep -v '^<no value>$' || true; }

container_nginx_raw() { docker exec "$1" nginx -v 2>&1 | head -n1 || true; }

container_has_nginx() {
  local c="$1" img
  img="$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null || true)"
  if [[ "$img" == *nginx* || "$img" == *openresty* ]]; then return 0; fi
  docker exec "$c" nginx -v >/dev/null 2>&1 && return 0
  return 1
}

inventory_docker() {
  $HAS_DOCKER || return 0
  local c raw v
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    container_has_nginx "$c" || continue
    DOCKER_NGINX+=("$c")
    DOCKER_NGINX_N=$((DOCKER_NGINX_N + 1))
    raw="$(container_nginx_raw "$c")"
    v="$(extract_version "$raw")"
    if [[ -z "$v" ]]; then
      warn "Docker $c: не смог прочитать версию nginx"
    elif printf '%s' "$raw" | grep -qi openresty; then
      warn "Docker $c: OpenResty $v (свой цикл релизов)"
    elif [[ -n "$(vuln_list "$v")" ]]; then
      warn "Docker $c: nginx $v — УЯЗВИМ"
    else
      ok "Docker $c: nginx $v"
    fi
  done < <(docker ps --format '{{.Names}}' 2>/dev/null)

  # контейнеры в рестарт-лупе / остановленные — только предупреждаем
  local stopped
  stopped="$(docker ps -a --filter status=exited --filter status=created --format '{{.Names}} {{.Image}}' 2>/dev/null \
             | awk '/nginx|openresty/{print $1}' | tr '\n' ' ')"
  [[ -n "$stopped" ]] && warn "остановленные контейнеры с nginx (не трогаю): $stopped"
}

image_nginx_version() {
  docker run --rm --entrypoint nginx "$1" -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

image_is_local_build() {
  local n
  n="$(docker image inspect "$1" --format '{{len .RepoDigests}}' 2>/dev/null || echo 0)"
  [[ "${n:-0}" == "0" ]]
}

# nginx:1.25.3-alpine + 1.30.4 → nginx:1.30.4-alpine
bump_ref() {
  local ref="$1" target="$2" name tag suffix
  [[ "$ref" != *:* ]] && return 1
  name="${ref%:*}"; tag="${ref##*:}"
  # registry:5000/nginx — двоеточие от порта, тега нет
  [[ "$tag" == *"/"* ]] && return 1
  if [[ "$tag" =~ ^([0-9]+(\.[0-9]+)*)(.*)$ ]]; then
    suffix="${BASH_REMATCH[3]}"
    printf '%s:%s%s' "$name" "$target" "$suffix"
    return 0
  fi
  return 1
}

pull_quiet() { docker pull "$1" >/dev/null 2>&1; }

setup_compose_cmd() {
  local wd="$1" proj="$2" files="$3" f
  COMPOSE_CMD=()
  if docker compose version >/dev/null 2>&1; then COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE_CMD=(docker-compose)
  else return 1; fi
  [[ -d "$wd" ]] && COMPOSE_CMD+=(--project-directory "$wd")
  [[ -n "$proj" ]] && COMPOSE_CMD+=(-p "$proj")
  if [[ -n "$files" ]]; then
    local -a fs; IFS=',' read -r -a fs <<< "$files"
    for f in "${fs[@]:-}"; do [[ -f "$f" ]] && COMPOSE_CMD+=(-f "$f"); done
  else
    for f in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
      [[ -f "$wd/$f" ]] && { COMPOSE_CMD+=(-f "$wd/$f"); break; }
    done
  fi
  return 0
}

compose_files_of() {
  local wd="$1" files="$2" f out=""
  if [[ -n "$files" ]]; then
    local -a fs; IFS=',' read -r -a fs <<< "$files"
    for f in "${fs[@]:-}"; do [[ -f "$f" ]] && out+="$f"$'\n'; done
  else
    for f in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
      [[ -f "$wd/$f" ]] && { out+="$wd/$f"$'\n'; break; }
    done
  fi
  printf '%s' "$out"
}

# Правим запиненный тег прямо в compose-файле или в .env
rewrite_pinned_tag() {
  local wd="$1" files="$2" old="$3" new="$4" f done=0
  while read -r f; do
    [[ -z "$f" ]] && continue
    if grep -qF "$old" "$f"; then
      cp -a "$f" "$f.ngxup-bak"
      sed -i "s|$(printf '%s' "$old" | sed 's/[|&\\]/\\&/g')|$(printf '%s' "$new" | sed 's/[|&\\]/\\&/g')|g" "$f"
      ok "  $f: $old → $new (бэкап $f.ngxup-bak)"
      done=1
    fi
  done <<< "$(compose_files_of "$wd" "$files")"

  if [[ $done -eq 0 && -f "$wd/.env" ]]; then
    local oldtag="${old##*:}" newtag="${new##*:}"
    if grep -qF "$oldtag" "$wd/.env"; then
      cp -a "$wd/.env" "$wd/.env.ngxup-bak"
      sed -i "s|${oldtag}|${newtag}|g" "$wd/.env"
      ok "  $wd/.env: $oldtag → $newtag"
      done=1
    fi
  fi
  [[ $done -eq 1 ]]
}

upgrade_compose_container() {
  local cname="$1" wd="$2" svc="$3" proj="$4" files="$5" curver="$6"
  local target; target="$(target_version "$NGINX_TRACK")"

  setup_compose_cmd "$wd" "$proj" "$files" || { manual "$cname (нет docker compose)"; return 1; }

  local ref newref=""
  ref="$(docker inspect -f '{{.Config.Image}}' "$cname" 2>/dev/null || true)"
  log "  compose: проект '$proj', сервис '$svc', образ '$ref'"

  if image_is_local_build "$ref"; then
    log "  образ собран локально — пересобираю с --pull"
    if $DRY_RUN; then warn "  [DRY-RUN] compose build --pull $svc && up -d $svc"; return 0; fi
    "${COMPOSE_CMD[@]}" build --pull "$svc" 2>&1 | tail -5 | sed 's/^/     /'
    "${COMPOSE_CMD[@]}" up -d --no-deps "$svc" 2>&1 | tail -5 | sed 's/^/     /'
  else
    # запинен ли тег
    local tag="${ref##*:}"
    if [[ "$ref" == *:* && "$tag" =~ ^[0-9]+\. ]]; then
      newref="$(bump_ref "$ref" "$target" || true)"
      if [[ -z "$newref" ]]; then
        manual "$cname (не смог разобрать тег '$ref')"
        return 1
      fi
      if $DRY_RUN; then
        warn "  [DRY-RUN] тег запинен: $ref → $newref, затем compose up -d --no-deps $svc"
        return 0
      fi
      log "  тег запинен ($ref), поднимаю до $newref"
      if ! pull_quiet "$newref"; then
        local alt
        alt="${ref%:*}:stable$(printf '%s' "$tag" | sed 's/^[0-9][0-9.]*//')"
        warn "  тега $newref нет, пробую $alt"
        pull_quiet "$alt" || { manual "$cname (нет подходящего тега для $ref)"; return 1; }
        newref="$alt"
      fi
      local iv; iv="$(image_nginx_version "$newref")"
      if [[ -n "$iv" && -n "$(vuln_list "$iv")" ]]; then
        err "  образ $newref содержит nginx $iv — всё ещё уязвим, не пересоздаю"
        manual "$cname (нет непатченного образа для $ref)"
        return 1
      fi
      rewrite_pinned_tag "$wd" "$files" "$ref" "$newref" \
        || { manual "$cname (тег $ref задан не литералом — правь compose вручную)"; return 1; }
      "${COMPOSE_CMD[@]}" up -d --no-deps "$svc" 2>&1 | tail -5 | sed 's/^/     /'
    else
      if $DRY_RUN; then warn "  [DRY-RUN] compose pull $svc && up -d --no-deps $svc"; return 0; fi
      "${COMPOSE_CMD[@]}" pull "$svc" 2>&1 | tail -3 | sed 's/^/     /'
      "${COMPOSE_CMD[@]}" up -d --no-deps "$svc" 2>&1 | tail -5 | sed 's/^/     /'
    fi
  fi

  sleep 3
  local newname
  newname="$(docker ps --filter "label=com.docker.compose.project=$proj" \
                       --filter "label=com.docker.compose.service=$svc" \
                       --format '{{.Names}}' 2>/dev/null | head -n1)"
  [[ -n "$newname" ]] && cname="$newname"
  verify_container "$cname" "$curver"
}

# ---------------------------------------------------------------------------
# raw `docker run` — пересоздание по слепку inspect
# ---------------------------------------------------------------------------

RUNARGS_PY='
import json, sys
def load(path):
    try:
        d = json.load(open(path))
        return d[0] if isinstance(d, list) and d else {}
    except Exception:
        return {}

try:
    c = json.load(open(sys.argv[1]))[0]
except Exception as e:
    sys.stderr.write("parse: %s\n" % e); sys.exit(3)

oldimg = load(sys.argv[2])          # образ, из которого контейнер создан
newimg = load(sys.argv[3])          # образ, на который переезжаем
new_image = sys.argv[4]
cfg, host = c.get("Config", {}), c.get("HostConfig", {})
icfg = oldimg.get("Config", {}) or {}
ncfg = newimg.get("Config", {}) or {}
have_old = bool(icfg)

nm = host.get("NetworkMode", "")
if nm.startswith("container:"):
    sys.stderr.write("unsupported: NetworkMode=container:*\n"); sys.exit(4)
if c.get("Config", {}).get("Labels", {}).get("com.docker.swarm.service.id"):
    sys.stderr.write("unsupported: swarm service\n"); sys.exit(4)

a = ["run", "-d", "--name", c["Name"].lstrip("/")]

rp = host.get("RestartPolicy") or {}
if rp.get("Name") and rp["Name"] != "no":
    v = rp["Name"]
    if v == "on-failure" and rp.get("MaximumRetryCount"):
        v += ":%d" % rp["MaximumRetryCount"]
    a += ["--restart", v]

for b in host.get("Binds") or []:
    a += ["-v", b]
for m in c.get("Mounts") or []:
    if m.get("Type") == "tmpfs":
        a += ["--tmpfs", m.get("Destination", "")]

for hp, bl in (host.get("PortBindings") or {}).items():
    for b in bl or []:
        ip, p = b.get("HostIp", ""), b.get("HostPort", "")
        a += ["-p", ("%s:%s:%s" % (ip, p, hp)) if ip else ("%s:%s" % (p, hp))]

# Переносим только то, что задал пользователь, а не то, что пришло из образа.
# Сравниваем со СТАРЫМ образом — иначе, например, NGINX_VERSION=1.24.0
# уехал бы в новый контейнер как явный -e и остался бы врать про версию.
base = set(icfg.get("Env") or [])
nkeys = set(e.split("=", 1)[0] for e in (ncfg.get("Env") or []))
for e in cfg.get("Env") or []:
    if e in base:
        continue
    if not have_old and e.split("=", 1)[0] in nkeys:
        continue    # старого образа нет — отбрасываем по имени переменной
    a += ["-e", e]

for k, v in (cfg.get("Labels") or {}).items():
    if k.startswith("com.docker.") or k.startswith("org.opencontainers.image."):
        continue
    if (icfg.get("Labels") or {}).get(k) == v:
        continue
    a += ["--label", "%s=%s" % (k, v)]

nets = (c.get("NetworkSettings", {}).get("Networks") or {})
primary = None
if nets:
    primary = nm if nm in nets else sorted(nets)[0]
if primary in ("bridge", "default") and nm in ("", "default", "bridge"):
    primary = None
elif nm in ("host", "none"):
    primary = nm
if primary:
    a += ["--network", primary]
    ep = nets.get(primary, {}) or {}
    for al in ep.get("Aliases") or []:
        if not c["Id"].startswith(al):
            a += ["--network-alias", al]
    if (ep.get("IPAMConfig") or {}).get("IPv4Address"):
        a += ["--ip", ep["IPAMConfig"]["IPv4Address"]]

for cp in host.get("CapAdd") or []:  a += ["--cap-add", cp]
for cp in host.get("CapDrop") or []: a += ["--cap-drop", cp]
if host.get("Privileged"): a += ["--privileged"]
for k, v in (host.get("Sysctls") or {}).items(): a += ["--sysctl", "%s=%s" % (k, v)]
for h in host.get("ExtraHosts") or []: a += ["--add-host", h]
for d in host.get("Dns") or []: a += ["--dns", d]
for s in host.get("SecurityOpt") or []: a += ["--security-opt", s]
for g in host.get("GroupAdd") or []: a += ["--group-add", g]
for d in host.get("Devices") or []:
    a += ["--device", "%s:%s:%s" % (d.get("PathOnHost"), d.get("PathInContainer"), d.get("CgroupPermissions", "rwm"))]
for u in host.get("Ulimits") or []:
    a += ["--ulimit", "%s=%s:%s" % (u["Name"], u["Soft"], u["Hard"])]

lc = host.get("LogConfig") or {}
if lc.get("Type") and lc["Type"] not in ("json-file", ""):
    a += ["--log-driver", lc["Type"]]
    for k, v in (lc.get("Config") or {}).items():
        a += ["--log-opt", "%s=%s" % (k, v)]

if host.get("IpcMode") in ("host",): a += ["--ipc", "host"]
if host.get("PidMode") in ("host",): a += ["--pid", "host"]
if host.get("ShmSize") and host["ShmSize"] != 67108864:
    a += ["--shm-size", str(host["ShmSize"])]
if host.get("Memory"): a += ["--memory", str(host["Memory"])]
if host.get("NanoCpus"): a += ["--cpus", str(host["NanoCpus"] / 1e9)]
if host.get("CgroupParent"): a += ["--cgroup-parent", host["CgroupParent"]]
if host.get("Runtime") and host["Runtime"] != "runc": a += ["--runtime", host["Runtime"]]
if cfg.get("User") and cfg["User"] != icfg.get("User", ""): a += ["--user", cfg["User"]]
if cfg.get("WorkingDir") and cfg["WorkingDir"] != icfg.get("WorkingDir", ""): a += ["-w", cfg["WorkingDir"]]
if cfg.get("Hostname") and not c["Id"].startswith(cfg["Hostname"]): a += ["--hostname", cfg["Hostname"]]

if cfg.get("Entrypoint") and cfg["Entrypoint"] != icfg.get("Entrypoint"):
    a += ["--entrypoint", cfg["Entrypoint"][0]]

a += [new_image]

if cfg.get("Cmd") and cfg["Cmd"] != icfg.get("Cmd"):
    a += list(cfg["Cmd"])

extra = [n for n in nets if n != primary]
sys.stdout.write("\x00".join(a) + "\x00")
sys.stderr.write("EXTRA_NETWORKS=%s\n" % ",".join(extra))
'

recreate_raw_container() {
  local cname="$1" curver="$2"
  local target; target="$(target_version "$NGINX_TRACK")"

  if ! $ALLOW_RECREATE; then
    manual "$cname (raw docker run; запуск с --no-recreate)"
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    manual "$cname (raw docker run; нужен python3 для разбора inspect)"
    return 1
  fi

  local ref newref
  ref="$(docker inspect -f '{{.Config.Image}}' "$cname")"
  if [[ "$ref" == *:* && "${ref##*:}" =~ ^[0-9]+\. ]]; then
    newref="$(bump_ref "$ref" "$target" || true)"
  else
    newref="$ref"
  fi
  [[ -z "$newref" ]] && { manual "$cname (не разобрал тег $ref)"; return 1; }

  if $DRY_RUN; then
    warn "  [DRY-RUN] пересоздание $cname: $ref → $newref (rename-стратегия с откатом)"
    return 0
  fi

  pull_quiet "$newref" || { manual "$cname (не скачался $newref)"; return 1; }
  local iv; iv="$(image_nginx_version "$newref")"
  if [[ -n "$iv" && -n "$(vuln_list "$iv")" ]]; then
    err "  $newref содержит уязвимый nginx $iv — не пересоздаю"
    manual "$cname (нет непатченного образа)"
    return 1
  fi

  local insp oldimg newimg
  insp="$BACKUP_DIR/inspect-$cname.json"
  oldimg="$BACKUP_DIR/image-old-$cname.json"
  newimg="$BACKUP_DIR/image-new-$cname.json"
  docker inspect "$cname" > "$insp"
  docker image inspect "$ref"    > "$oldimg" 2>/dev/null || echo '[{}]' > "$oldimg"
  docker image inspect "$newref" > "$newimg" 2>/dev/null || echo '[{}]' > "$newimg"

  local argfile errfile extra_nets item
  argfile="$BACKUP_DIR/runargs-$cname.bin"
  errfile="$BACKUP_DIR/runargs-$cname.err"
  if ! python3 -c "$RUNARGS_PY" "$insp" "$oldimg" "$newimg" "$newref" > "$argfile" 2>"$errfile"; then
    warn "  не могу безопасно воспроизвести параметры запуска: $(grep -v '^EXTRA_NETWORKS=' "$errfile" | head -3 | tr '\n' ' ')"
    manual "$cname (пересоздай вручную по $insp)"
    return 1
  fi
  extra_nets="$(sed -n 's/^EXTRA_NETWORKS=//p' "$errfile")"

  local -a runargs=()
  while IFS= read -r -d '' item; do runargs+=("$item"); done < "$argfile"

  if [[ ${#runargs[@]} -lt 3 ]]; then
    manual "$cname (пустые параметры запуска)"
    return 1
  fi

  printf '%s ' docker "${runargs[@]}" > "$BACKUP_DIR/runcmd-$cname.txt"; echo >> "$BACKUP_DIR/runcmd-$cname.txt"
  log "  команда пересоздания сохранена: $BACKUP_DIR/runcmd-$cname.txt"

  log "  останавливаю и переименовываю $cname → ${cname}-preupgrade"
  docker stop "$cname" >/dev/null 2>&1 || true
  docker rename "$cname" "${cname}-preupgrade" || { manual "$cname (rename не прошёл)"; return 1; }

  if ! docker "${runargs[@]}" >/dev/null 2>&1; then
    err "  запуск нового контейнера не удался — откатываю"
    docker rm -f "$cname" >/dev/null 2>&1 || true
    docker rename "${cname}-preupgrade" "$cname" && docker start "$cname" >/dev/null 2>&1
    manual "$cname (не стартанул новый контейнер, старый возвращён)"
    return 1
  fi

  local n
  for n in ${extra_nets//,/ }; do
    [[ -n "$n" ]] && docker network connect "$n" "$cname" >/dev/null 2>&1 || true
  done

  sleep 4
  if ! verify_container "$cname" "$curver"; then
    err "  проверка не пройдена — откатываю на ${cname}-preupgrade"
    docker rm -f "$cname" >/dev/null 2>&1 || true
    docker rename "${cname}-preupgrade" "$cname" && docker start "$cname" >/dev/null 2>&1
    manual "$cname (новый контейнер не прошёл проверку, старый возвращён)"
    return 1
  fi

  ok "  $cname пересоздан. Старый контейнер оставлен как ${cname}-preupgrade"
  note "убедись, что всё работает, потом: docker rm ${cname}-preupgrade"
  acted "docker: $cname пересоздан на $newref"
  return 0
}

verify_container() {
  local c="$1" oldver="$2" v
  if ! docker ps --format '{{.Names}}' | grep -qxF "$c"; then
    err "  контейнер $c не запущен после обновления"
    docker logs --tail 30 "$c" 2>&1 | sed 's/^/     /' || true
    EXIT_CODE=1
    return 1
  fi
  if ! docker exec "$c" nginx -t >/dev/null 2>&1; then
    warn "  nginx -t внутри $c не проходит:"
    docker exec "$c" nginx -t 2>&1 | sed 's/^/     /' || true
  fi
  v="$(extract_version "$(container_nginx_raw "$c")")"
  if [[ -z "$v" ]]; then
    warn "  не прочитал версию в $c"
    return 1
  fi
  if [[ -n "$(vuln_list "$v")" ]]; then
    err "  $c: nginx $v всё ещё уязвим"
    manual "$c (после обновления образа версия $v всё ещё уязвима)"
    EXIT_CODE=1
    return 1
  fi
  ok "  $c: nginx $oldver → $v"
  acted "docker: $c обновлён до nginx $v"
  return 0
}

upgrade_docker() {
  header "Docker"
  if $SKIP_DOCKER; then log "--skip-docker → пропуск"; return 0; fi
  if ! $HAS_DOCKER; then log "Docker не найден/не запущен → пропуск"; return 0; fi
  if [[ $DOCKER_NGINX_N -eq 0 ]]; then log "контейнеров с nginx нет → пропуск"; return 0; fi

  local c raw v wd svc proj files
  for c in "${DOCKER_NGINX[@]:-}"; do
    [[ -z "$c" ]] && continue
    raw="$(container_nginx_raw "$c")"
    v="$(extract_version "$raw")"

    if printf '%s' "$raw" | grep -qi openresty; then
      manual "$c (OpenResty $v — обновляется отдельно от nginx)"
      continue
    fi
    if [[ -z "$v" ]]; then
      manual "$c (не читается версия nginx)"
      continue
    fi
    if [[ -z "$(vuln_list "$v")" ]]; then
      ok "$c: nginx $v — уязвимостей нет, пропуск"
      continue
    fi

    log "Контейнер $c (nginx $v) — уязвим"
    docker inspect "$c" > "$BACKUP_DIR/inspect-$c.json" 2>/dev/null || true

    wd="$(dlabel "$c" com.docker.compose.project.working_dir)"
    svc="$(dlabel "$c" com.docker.compose.service)"
    proj="$(dlabel "$c" com.docker.compose.project)"
    files="$(dlabel "$c" com.docker.compose.project.config_files)"

    if [[ -n "$svc" && ( -n "$files" || -d "$wd" ) ]]; then
      upgrade_compose_container "$c" "$wd" "$svc" "$proj" "$files" "$v" || true
    else
      log "  не compose — пересоздаю по слепку docker inspect"
      recreate_raw_container "$c" "$v" || true
    fi
  done
}

# ============================================================================
# ПРОЧИЕ ИНСТАЛЛЯЦИИ NGINX (только детект — трогать не наше дело)
# ============================================================================

detect_other_nginx() {
  if command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -qi '^nginx'; then
    manual "nginx установлен через snap — обновляй: snap refresh nginx"
  fi
  if command -v kubectl >/dev/null 2>&1 && kubectl get pods -A 2>/dev/null | grep -qi 'ingress-nginx'; then
    warn "в кластере найден ingress-nginx"
    manual "ingress-nginx: проект Kubernetes закрыт в марте 2026, апстрим-патча не будет — мигрируй на другой ingress"
  fi
}

# ============================================================================
# ОТЧЁТ
# ============================================================================

json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | tr -d '\n\r'; }

json_arr() {
  local first=1 item
  printf '['
  for item in "$@"; do
    [[ -z "$item" ]] && continue
    [[ $first -eq 0 ]] && printf ','
    printf '"%s"' "$(json_esc "$item")"
    first=0
  done
  printf ']'
}

build_json() {
  local sys_src="distro"
  $SYS_FROM_NGINXORG && sys_src="nginx.org"
  $SYS_FROM_SOURCE && sys_src="source"

  local cves=() c
  while IFS='|' read -r c _; do [[ -n "$c" ]] && cves+=("$c"); done <<< "$SYS_VULNS"

  local dockerj="[" first=1 name raw v vul
  for name in "${DOCKER_NGINX[@]:-}"; do
    [[ -z "$name" ]] && continue
    raw="$(container_nginx_raw "$name")"; v="$(extract_version "$raw")"
    vul=false; [[ -n "$v" && -n "$(vuln_list "$v")" ]] && vul=true
    [[ $first -eq 0 ]] && dockerj+=","
    dockerj+="{\"name\":\"$(json_esc "$name")\",\"version\":\"$(json_esc "${v:-unknown}")\",\"vulnerable\":$vul}"
    first=0
  done
  dockerj+="]"

  cat <<__JSON__
{
  "script_version": "$SCRIPT_VERSION",
  "host": "$(json_esc "$(hostname -f 2>/dev/null || hostname)")",
  "timestamp": "$(date -Is)",
  "dry_run": $DRY_RUN,
  "exit_code": $EXIT_CODE,
  "log": "$(json_esc "$LOG_FILE")",
  "backup": "$(json_esc "$BACKUP_DIR")",
  "os": "$(json_esc "$OS_PRETTY")",
  "system": {
    "present": $HAS_SYSTEM_NGINX,
    "version": "$(json_esc "$SYS_VERSION")",
    "package": "$(json_esc "$SYS_PKG")",
    "package_version": "$(json_esc "$SYS_PKGVER")",
    "source": "$sys_src",
    "patched_by_distro": $SYS_PATCHED_BY_DISTRO,
    "distro_reverted_patches": $(json_arr "${DISTRO_REVERTED_CVES:-}"),
    "open_cves": $(json_arr "${cves[@]:-}")
  },
  "docker": $dockerj,
  "config_fixes": $(json_arr "${CONF_FIXES[@]:-}"),
  "actions": $(json_arr "${ACTIONS[@]:-}"),
  "manual": $(json_arr "${NEEDS_MANUAL[@]:-}")
}
__JSON__
}

print_summary() {
  header "Итог"
  echo
  echo "  ${BOLD}Хост:${NC}    $(hostname -f 2>/dev/null || hostname)"
  echo "  ${BOLD}Лог:${NC}     $LOG_FILE"
  [[ -n "$BACKUP_DIR" ]] && echo "  ${BOLD}Бэкап:${NC}   $BACKUP_DIR"
  echo

  if $HAS_SYSTEM_NGINX; then
    local v; v="$(extract_version "$(nginx_raw_version nginx)")"
    local rest; rest="$(open_cves "${v:-unknown}")"
    if [[ -n "$rest" ]]; then
      echo "  Системный nginx:  ${RED}${v:-unknown} — остались CVE: $(echo "$rest" | cut -d'|' -f1 | tr '\n' ' ')${NC}"
    elif $SYS_PATCHED_BY_DISTRO; then
      echo "  Системный nginx:  ${GREEN}${v} ✓${NC} ${DIM}(пакет $SYS_PKGVER, патчи дистрибутива)${NC}"
    else
      echo "  Системный nginx:  ${GREEN}${v} ✓${NC}"
    fi
  fi

  local c raw dv
  for c in "${DOCKER_NGINX[@]:-}"; do
    [[ -z "$c" ]] && continue
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qxF "$c" || continue
    raw="$(container_nginx_raw "$c")"; dv="$(extract_version "$raw")"
    if [[ -n "$dv" && -z "$(vuln_list "$dv")" ]]; then
      echo "  Docker $c:  ${GREEN}${dv} ✓${NC}"
    else
      echo "  Docker $c:  ${RED}${dv:-unknown} — уязвим${NC}"
    fi
  done

  if [[ $CONF_FIXES_N -gt 0 ]]; then
    echo
    echo "  ${BOLD}Починено в конфигурации:${NC}"
    local f; for f in "${CONF_FIXES[@]}"; do echo "    ${GREEN}✓${NC} $f"; done
  fi

  if [[ $NEEDS_MANUAL_N -gt 0 ]]; then
    echo
    echo "  ${YELLOW}${BOLD}Требуют ручной работы:${NC}"
    local m; for m in "${NEEDS_MANUAL[@]}"; do echo "    ${YELLOW}⚠${NC} $m"; done
  fi

  echo
  if $DRY_RUN; then
    echo "  ${CYAN}${BOLD}DRY-RUN — ничего не менялось${NC}"
  else
    case "$EXIT_CODE" in
      0) echo "  ${GREEN}${BOLD}РЕЗУЛЬТАТ: ЧИСТО${NC}" ;;
      1) echo "  ${RED}${BOLD}РЕЗУЛЬТАТ: ОШИБКА${NC}" ;;
      2) echo "  ${YELLOW}${BOLD}РЕЗУЛЬТАТ: ЧАСТИЧНО${NC}" ;;
    esac
  fi
  echo
}

emit_reports() {
  local js; js="$(build_json)"
  if [[ -n "$JSON_OUT" ]]; then
    printf '%s\n' "$js" > "$JSON_OUT" && log "JSON-отчёт: $JSON_OUT"
  fi
  if [[ -n "$WEBHOOK" ]] && command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 15 -X POST -H 'Content-Type: application/json' \
      -d "$js" "$WEBHOOK" >/dev/null 2>&1 \
      && log "отчёт отправлен на webhook" || warn "webhook не ответил"
  fi
}

# ============================================================================
# SYSTEMD-ТАЙМЕР
# ============================================================================

install_timer() {
  command -v systemctl >/dev/null 2>&1 || die "systemd не найден"
  local dst="/usr/local/sbin/nginx-upgrade.sh"
  install -m 0755 "$SCRIPT_SELF" "$dst" || die "не смог скопировать скрипт в $dst"

  cat > /etc/systemd/system/nginx-updater.service <<__SVC__
[Unit]
Description=nginx security updater
Documentation=https://github.com/tagashi666/nginx-updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$dst --quiet --json /var/log/nginx-upgrade/last.json
TimeoutStartSec=1800
__SVC__

  cat > /etc/systemd/system/nginx-updater.timer <<'__TMR__'
[Unit]
Description=ежедневная проверка обновлений безопасности nginx

[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
__TMR__

  systemctl daemon-reload
  systemctl enable --now nginx-updater.timer >/dev/null 2>&1
  ok "таймер установлен: nginx-updater.timer (ежедневно, разброс до 4ч)"
  note "проверить: systemctl list-timers nginx-updater.timer"
  note "разовый прогон: systemctl start nginx-updater.service"
  flush_log
  exit 0
}

uninstall_timer() {
  systemctl disable --now nginx-updater.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/nginx-updater.timer /etc/systemd/system/nginx-updater.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "таймер снят"
  flush_log
  exit 0
}

# ============================================================================
# MAIN
# ============================================================================

main() {
  bootstrap
  detect_os

  case "${DO_TIMER:-}" in
    install)   install_timer ;;
    uninstall) uninstall_timer ;;
  esac

  header "Pre-flight"
  log "nginx-upgrade.sh $SCRIPT_VERSION"
  log "Хост: $(hostname -f 2>/dev/null || hostname)"
  log "OS: ${OS_PRETTY:-$OS_ID} (пакеты: $PKG_FAMILY)"
  log "Режим: $($DRY_RUN && echo 'DRY-RUN' || echo 'APPLY'), ветка: $NGINX_TRACK"

  if $REFRESH_DB; then
    if refresh_cve_db; then
      ok "база уязвимостей обновлена с nginx.org ($(grep -c '^CVE-' <<< "$CVE_DB") записей)"
    else
      log "nginx.org недоступен — использую встроенную базу (слепок 2026-08-07)"
    fi
  fi
  log "Целевая версия: >= $(target_version "$NGINX_TRACK") ($NGINX_TRACK)"

  inventory_system
  detect_docker

  if ! $HAS_SYSTEM_NGINX && ! $HAS_DOCKER; then
    log "ни системного nginx, ни Docker — делать нечего"
    print_summary
    flush_log
    exit 0
  fi

  header "Инвентаризация"
  if $HAS_SYSTEM_NGINX; then
    local src="дистрибутив"
    $SYS_FROM_NGINXORG && src="nginx.org"
    $SYS_FROM_SOURCE && src="сборка из исходников"
    log "системный nginx $SYS_VERSION — пакет ${SYS_PKG:-нет} ${SYS_PKGVER:+($SYS_PKGVER)} [$src]"
    log "конфиг: $SYS_CONF"
  fi

  make_backup
  inventory_docker

  local before_fixes=$CONF_FIXES_N
  upgrade_system || true

  if $DRY_RUN; then
    repair_config_dryrun
  else
    repair_config || true
    if [[ $CONF_FIXES_N -gt $before_fixes ]] || [[ $ACTIONS_N -gt 0 ]]; then
      header "Проверка и перезапуск"
      verify_and_rollback "system" || true
    fi
  fi

  upgrade_docker || true
  detect_other_nginx

  print_summary
  emit_reports
  flush_log
  exit $EXIT_CODE
}

repair_config_dryrun() {
  $HAS_SYSTEM_NGINX || return 0
  header "Проверка конфигурации (dry-run)"
  local d issues=0
  for d in "$SYS_PREFIX/sites-enabled" "$SYS_PREFIX/conf.d"; do
    [[ -d "$d" ]] || continue
    find "$d" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | head -1 | grep -q . || continue
    if ! conf_includes_dir "$d"; then
      warn "нет include для $d — сайты оттуда НЕ обслуживаются. Был бы добавлен."
      issues=1
      manual "в $SYS_CONF отсутствует include для $d"
    fi
  done
  local u
  u="$(grep -hE '^[[:space:]]*user[[:space:]]+' "$SYS_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1 | awk '{print $2}' | tr -d ';')"
  if [[ -n "$u" ]] && ! id -u "$u" >/dev/null 2>&1; then
    warn "пользователь '$u' из конфига не существует. Был бы создан."
    issues=1
  fi
  if $FIX_HTTP2 && ver_ge "$SYS_VERSION" "1.25.1" \
     && grep -rqE '^[^#]*listen[^;]*[[:space:]]http2([[:space:]]|;)' "$SYS_PREFIX" 2>/dev/null; then
    warn "найден deprecated 'listen ... http2'. Был бы переписан на 'http2 on;'."
    issues=1
  fi
  [[ $issues -eq 0 ]] && ok "конфигурация в порядке"
  return 0
}

# Позволяет `NGXUP_LIB_ONLY=1 source nginx-upgrade.sh` для тестов/переиспользования
if [[ "${NGXUP_LIB_ONLY:-}" != "1" ]]; then
  main "$@"
fi
