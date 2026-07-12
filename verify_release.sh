#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
cd -- "$(dirname -- "$0")"

python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 -m json.tool config/edu_policy.example.json >/dev/null
bash -n install_fedora.sh install_kali.sh run.sh run_teacher.sh configure_teacher_mode.sh verify_release.sh
python3 foxvuln.py --version
python3 foxvuln.py --show-policy >/dev/null
python3 foxvuln.py --demo --output ./_release_demo >/dev/null
rm -rf ./_release_demo

echo "Release EDU verificada correctamente."
