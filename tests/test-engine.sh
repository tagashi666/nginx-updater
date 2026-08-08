#!/usr/bin/env bash
# Юнит-тесты движка версий/CVE и авторемонта конфига
NGXUP_LIB_ONLY=1 . "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/nginx-upgrade.sh"
PASS=0; FAIL=0
t() { # t <описание> <ожидание> <факт>
  if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $1 | ждал '$2' получил '$3'"; fi
}
tv() { # уязвима ли версия: 1 = да
  local v="$1" want="$2" got
  [[ -n "$(vuln_list "$v")" ]] && got=1 || got=0
  t "vuln($v)" "$want" "$got"
}

echo "--- сравнение версий ---"
t "cmp 1.30.0<1.30.1" "-1" "$(ver_cmp 1.30.0 1.30.1)"
t "cmp 1.9.0<1.10.0"  "-1" "$(ver_cmp 1.9.0 1.10.0)"
t "cmp 1.30.4=1.30.4"  "0" "$(ver_cmp 1.30.4 1.30.4)"
t "cmp 1.31.0>1.30.9"  "1" "$(ver_cmp 1.31.0 1.30.9)"
t "cmp 1.30>1.30.0"    "0" "$(ver_cmp 1.30 1.30.0)"
t "branch 1.30.4"   "1.30" "$(ver_branch 1.30.4)"

echo "--- уязвимость upstream-версий (nginx.org advisories) ---"
tv 1.30.0 1   # Rift
tv 1.30.1 1   # закрыт Rift, но открыт CVE-2026-9256 и далее
tv 1.30.3 1   # открыт CVE-2026-42533/60005/56434
tv 1.30.4 0   # текущий безопасный stable
tv 1.30.5 0
tv 1.31.0 1
tv 1.31.2 1   # 42533 открыт
tv 1.31.3 0   # текущий безопасный mainline
tv 1.29.7 1   # ветка мертва, Rift не закрыт
tv 1.24.0 1   # Ubuntu 24.04 upstream-номер
tv 1.18.0 1
tv 1.32.0 0   # будущая ветка новее всех фиксов
tv 0.5.0  1   # 0.5.x попадает в диапазон charset-overread 0.3.50-1.30.0

echo "--- целевые версии ---"
t "target stable"   "1.30.4" "$(target_version stable)"
t "target mainline" "1.31.3" "$(target_version mainline)"

echo "--- severity gate ---"
t "1.30.0 имеет critical" "0" "$(has_severity_at_least "$(vuln_list 1.30.0)" critical; echo $?)"
t "1.30.3 не имеет critical" "1" "$(has_severity_at_least "$(vuln_list 1.30.3)" critical; echo $?)"
t "1.30.3 имеет major" "0" "$(has_severity_at_least "$(vuln_list 1.30.3)" major; echo $?)"
t "1.30.4 не имеет low" "1" "$(has_severity_at_least "$(vuln_list 1.30.4)" low; echo $?)"

echo "--- разбор строки nginx -v ---"
t "nginx" "1.30.4" "$(extract_version 'nginx version: nginx/1.30.4')"
t "openresty" "1.27.1" "$(extract_version 'nginx version: openresty/1.27.1.2')"
t "ubuntu" "1.24.0" "$(extract_version 'nginx version: nginx/1.24.0 (Ubuntu)')"

echo "--- bump_ref (теги docker) ---"
t "простой"   "nginx:1.30.4"          "$(bump_ref nginx:1.25.3 1.30.4)"
t "alpine"    "nginx:1.30.4-alpine"   "$(bump_ref nginx:1.25.3-alpine 1.30.4)"
t "две части" "nginx:1.30.4-bookworm" "$(bump_ref nginx:1.25-bookworm 1.30.4)"
t "приватный реестр" "reg.local:5000/nginx:1.30.4" "$(bump_ref reg.local:5000/nginx:1.24.0 1.30.4)"
t "без тега (порт)" "1" "$(bump_ref reg.local:5000/nginx 1.30.4 >/dev/null; echo $?)"
t "latest"    "1"                     "$(bump_ref nginx:latest 1.30.4 >/dev/null; echo $?)"

echo
echo "PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
