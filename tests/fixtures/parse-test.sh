NGXUP_LIB_ONLY=1 . ./nginx-upgrade.sh
# Офлайн-проверка парсера nginx.org/en/security_advisories.html на реальной разметке.
# Запуск: bash tests/fixtures/parse-test.sh
curl() { cat "$(dirname "${BASH_SOURCE[0]}")/advisories.html"; }
export -f curl 2>/dev/null || true
if refresh_cve_db; then
  echo "=== распарсено ==="; printf '%s\n' "$CVE_DB"
else
  echo "PARSER RETURNED FAILURE (мало записей — ожидаемо для мини-фикстуры)"
  echo "=== прямой прогон парсера ==="
  printf '%s\n' "$(cat "$(dirname "${BASH_SOURCE[0]}")/advisories.html")" \
    | sed -e 's/<[Bb][Rr][^>]*>/\n/g' -e 's/<[^>]*>/ /g' -e 's/&amp;/\&/g' -e 's/&nbsp;/ /g' \
    | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' \
    | awk '
      { if (match($0, /CVE-[0-9]+-[0-9]+/)) cve = substr($0, RSTART, RLENGTH)
        if ($0 ~ /^Severity:/) { sev = $2; gsub(/[^a-zA-Z]/, "", sev); sev = tolower(sev) }
        if ($0 ~ /^Not vulnerable:/) { nv = $0; sub(/^Not vulnerable:[ ]*/, "", nv) }
        if ($0 ~ /^Vulnerable:/) {
          vr = $0; sub(/^Vulnerable:[ ]*/, "", vr)
          if (cve != "" && nv != "" && nv !~ /none/ && vr !~ /Windows/ && vr !~ /^all/) {
            gsub(/\+/, "", nv); gsub(/[ ]/, "", nv); gsub(/[ ]/, "", vr)
            if (sev == "") sev = "medium"
            print cve "|" sev "|" vr "|" nv }
          cve = ""; sev = ""; nv = "" } }'
fi
