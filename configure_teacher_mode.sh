#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

cd -- "$(dirname -- "$0")"

teacher_user="${1:-${USER:-}}"
policy_source="${2:-config/edu_policy.example.json}"

if [[ -z "$teacher_user" ]]; then
  echo "Uso: $0 <usuario-docente> [archivo-politica.json]" >&2
  exit 2
fi
if ! getent passwd "$teacher_user" >/dev/null; then
  echo "El usuario '$teacher_user' no existe." >&2
  exit 2
fi
if [[ ! -f "$policy_source" ]]; then
  echo "No existe la política: $policy_source" >&2
  exit 2
fi

teacher_group="$(python3 - "$policy_source" <<'PYCODE'
import sys
from pathlib import Path
from foxvuln_policy import PolicyError, load_education_policy

try:
    policy = load_education_policy(Path(sys.argv[1]), require_secure=False)
except PolicyError as exc:
    raise SystemExit(f"Error de política: {exc}") from None
if not policy.teacher_mode_enabled:
    raise SystemExit("Error de política: teacher_mode_enabled debe ser true.")
print(policy.teacher_group)
PYCODE
)"

if [[ ! "$teacher_group" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
  echo "Nombre de grupo docente inválido: $teacher_group" >&2
  exit 2
fi

echo "[1/4] Creando grupo docente: $teacher_group"
sudo groupadd -f "$teacher_group"

echo "[2/4] Agregando $teacher_user al grupo"
sudo usermod -aG "$teacher_group" "$teacher_user"

echo "[3/4] Instalando política institucional"
sudo install -d -o root -g root -m 0755 /etc/foxvuln
sudo install -o root -g root -m 0644 "$policy_source" /etc/foxvuln/edu_policy.json

echo "[4/4] Validando política instalada"
python3 foxvuln.py --show-policy >/dev/null

echo
echo "Modo docente configurado para: $teacher_user"
echo "Cierre la sesión y vuelva a ingresar para actualizar la pertenencia al grupo."
echo "Luego ejecute: ./run_teacher.sh"
