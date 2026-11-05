#!/usr/bin/env bash
# Runner completo de Stage 2 — ejecuta los 4 pasos en orden
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "############################################"
echo "# Stage 2 — Runner completo"
echo "############################################"
echo

bash "${HERE}/code_1.sh"
echo
echo

bash "${HERE}/code_2.sh"
echo
echo

bash "${HERE}/code_3.sh"
echo
echo

bash "${HERE}/code_4.sh"
echo
echo

echo "############################################"
echo "# Loot guardado en: ${HOME}/nexacorp-loot/"
echo "############################################"
ls -la "${HOME}/nexacorp-loot/"
