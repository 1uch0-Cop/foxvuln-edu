#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

cd -- "$(dirname -- "$0")"

echo "[1/3] Instalando dependencias de FoxVuln EDU"
sudo dnf install -y python3 python3-tkinter nmap git unzip

echo "[2/3] Validando código y política de ejemplo"
python3 -m compileall -q .
python3 -m json.tool config/edu_policy.example.json >/dev/null

echo "[3/3] Ejecutando pruebas internas"
python3 -m unittest discover -s tests -v

echo
echo "Instalación base completada."
echo "Modo estudiante: ./run.sh"
echo "Demostración sin tráfico: python3 foxvuln.py --demo"
echo "Para habilitar modo docente: ./configure_teacher_mode.sh <usuario>"
