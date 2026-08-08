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

echo "--- распознавание отозванных дистрибутивом патчей ---"
CL_FIX=$(cat <<'CLEOF'
nginx (1.24.0-2ubuntu7.15) noble-security; urgency=medium

  * SECURITY REGRESSION: Security fix may break ABI (LP: #2161362)
    - debian/patches/CVE-2026-42533-*.patch: Disabled for now.

 -- Maintainer <m@example.com>  Mon, 20 Jul 2026 15:12:12 -0400

nginx (1.24.0-2ubuntu7.14) noble-security; urgency=medium

  * SECURITY UPDATE: DoS via map directive
    - debian/patches/CVE-2026-42533-1.patch: buffer overrun protection.
    - CVE-2026-42533

 -- Maintainer <m@example.com>  Tue, 01 Jul 2026 10:00:00 -0400

nginx (1.24.0-2ubuntu7.8) noble-security; urgency=medium

  * SECURITY UPDATE: heap overflow in rewrite module
    - CVE-2026-42945

 -- Maintainer <m@example.com>  Wed, 14 May 2026 10:00:00 -0400

nginx (1.22.1-9ubuntu1) lunar; urgency=medium

  * d/p/CVE-2022-41741_41742.patch: disabled duplicate atoms in Mp4
    (CVE-2022-41741, CVE-2022-41742)
  * Dropped:
      + debian/patches/CVE-2021-23017.patch: removed, replaced with upstream

 -- Maintainer <m@example.com>  Thu, 01 Jun 2023 10:00:00 -0400
CLEOF
)
changelog_raw() { printf '%s' "$CL_FIX"; }
PKG_FAMILY=deb; SYS_PKG=nginx
_out="$(distro_fixed_cves)"
_fix="$(grep '^F ' <<< "$_out" | cut -c3-)"
_rev="$(grep '^R ' <<< "$_out" | cut -c3-)"
t "отозванный патч распознан" "1" "$(grep -c 'CVE-2026-42533' <<< "$_rev")"
t "отозванный не попал в закрытые" "0" "$(grep -c 'CVE-2026-42533' <<< "$_fix")"
t "Rift остался закрытым" "1" "$(grep -c 'CVE-2026-42945' <<< "$_fix")"
t "'disabled duplicate atoms' не откат" "0" "$(grep -c 'CVE-2022-41741' <<< "$_rev")"
t "'replaced with upstream' не откат" "0" "$(grep -c 'CVE-2021-23017' <<< "$_rev")"


echo "--- устойчивость классификатора к грязному changelog ---"
CL_DIRTY=$(printf '%s\n' \
  'nginx (1.24.0-2ubuntu7.15) noble-security; urgency=medium' '' \
  '  * SECURITY REGRESSION: Security fix may break ABI (LP: #2161362)' \
  '    - debian/patches/CVE-2026-42533-*.patch: Disabled for now.' \
  '    - broken escapes \\x2F \\xZZ \\x %s %d' '' \
  ' -- M <m@e.com>  Mon, 20 Jul 2026 15:12:12 -0400' '' \
  'nginx (1.24.0-2ubuntu7.8) noble-security; urgency=medium' '' \
  '  * SECURITY UPDATE: heap overflow' \
  '    - CVE-2026-42945' '' \
  ' -- M <m@e.com>  Wed, 14 May 2026 10:00:00 -0400')
changelog_raw() { printf '%s' "$CL_DIRTY"; }
_o="$(distro_fixed_cves 2>/tmp/ngxup-t.err)"
t "битые \\x не ломают разбор" "0" "$(wc -c < /tmp/ngxup-t.err | tr -d ' ')"
t "откат распознан на грязном"  "1" "$(grep -c '^R CVE-2026-42533$' <<< "$_o")"
t "Rift закрыт на грязном"      "1" "$(grep -c '^F CVE-2026-42945$' <<< "$_o")"
rm -f /tmp/ngxup-t.err

echo "--- manual_drop снимает устаревшие пометки ---"
NEEDS_MANUAL=(); NEEDS_MANUAL_N=0; EXIT_CODE=0
manual "CVE-2026-42533: патч дистрибутива отозван, штатное обновление не поможет"
manual "обновить OpenResty вручную"
t "две пометки записаны" "2" "$NEEDS_MANUAL_N"
t "EXIT_CODE стал 2"     "2" "$EXIT_CODE"
manual_drop "патч дистрибутива отозван"
t "осталась одна"        "1" "$NEEDS_MANUAL_N"
t "осталась нужная"      "1" "$(printf '%s\n' "${NEEDS_MANUAL[@]}" | grep -c OpenResty)"
manual_drop "OpenResty"
t "пусто"                "0" "$NEEDS_MANUAL_N"
t "EXIT_CODE вернулся в 0" "0" "$EXIT_CODE"


echo
echo "PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]

CL_FIX=$(cat <<'CLEOF'
nginx (1.24.0-2ubuntu7.15) noble-security; urgency=medium

  * SECURITY REGRESSION: Security fix may break ABI (LP: #2161362)
    - debian/patches/CVE-2026-42533-*.patch: Disabled for now.

 -- Maintainer <m@example.com>  Mon, 20 Jul 2026 15:12:12 -0400

nginx (1.24.0-2ubuntu7.14) noble-security; urgency=medium

  * SECURITY UPDATE: DoS via map directive
    - debian/patches/CVE-2026-42533-1.patch: buffer overrun protection.
    - CVE-2026-42533

 -- Maintainer <m@example.com>  Tue, 01 Jul 2026 10:00:00 -0400

nginx (1.24.0-2ubuntu7.8) noble-security; urgency=medium

  * SECURITY UPDATE: heap overflow in rewrite module
    - CVE-2026-42945

 -- Maintainer <m@example.com>  Wed, 14 May 2026 10:00:00 -0400

nginx (1.22.1-9ubuntu1) lunar; urgency=medium

  * d/p/CVE-2022-41741_41742.patch: disabled duplicate atoms in Mp4
    (CVE-2022-41741, CVE-2022-41742)
  * Dropped:
      + debian/patches/CVE-2021-23017.patch: removed, replaced with upstream

 -- Maintainer <m@example.com>  Thu, 01 Jun 2023 10:00:00 -0400
CLEOF
)
changelog_raw() { printf '%s' "$CL_FIX"; }
PKG_FAMILY=deb; SYS_PKG=nginx
_out="$(distro_fixed_cves)"
_fix="$(grep '^F ' <<< "$_out" | cut -c3-)"
_rev="$(grep '^R ' <<< "$_out" | cut -c3-)"
t "отозванный патч распознан" "1" "$(grep -c 'CVE-2026-42533' <<< "$_rev")"
t "отозванный не попал в закрытые" "0" "$(grep -c 'CVE-2026-42533' <<< "$_fix")"
t "Rift остался закрытым" "1" "$(grep -c 'CVE-2026-42945' <<< "$_fix")"
t "'disabled duplicate atoms' не откат" "0" "$(grep -c 'CVE-2022-41741' <<< "$_rev")"
t "'replaced with upstream' не откат" "0" "$(grep -c 'CVE-2021-23017' <<< "$_rev")"
