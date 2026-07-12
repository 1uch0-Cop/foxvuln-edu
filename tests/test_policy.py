# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

from foxvuln_policy import (
    DEFAULT_POLICY,
    PolicyError,
    STUDENT_MODE,
    STUDENT_PROFILE,
    TEACHER_MODE,
    TEACHER_PROFILE,
    allowed_profiles,
    load_education_policy,
    policy_from_mapping,
    resolve_mode,
    validate_educational_target,
)


VALID_POLICY = {
    "schema_version": 1,
    "institution": "Escuela de prueba",
    "laboratory": "Red aislada",
    "allowed_networks": ["10.10.10.0/24", "192.168.56.0/24"],
    "allowed_targets": ["127.0.0.1"],
    "student_profiles": [STUDENT_PROFILE],
    "teacher_profiles": [STUDENT_PROFILE, TEACHER_PROFILE],
    "teacher_group": "foxvuln-teachers",
    "teacher_mode_enabled": True,
}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy_from_mapping(VALID_POLICY, source="test")

    def test_default_institution_is_hackcop(self):
        self.assertEqual(DEFAULT_POLICY.institution, "Hackcop")

    def test_allowlist_accepts_only_configured_lab(self):
        self.assertEqual(validate_educational_target("10.10.10.25", self.policy), "10.10.10.25")
        self.assertEqual(validate_educational_target("127.0.0.1", self.policy), "127.0.0.1")
        with self.assertRaises(PolicyError):
            validate_educational_target("192.168.1.10", self.policy)
        with self.assertRaises(PolicyError):
            validate_educational_target("8.8.8.8", self.policy)
        with self.assertRaises(PolicyError):
            validate_educational_target("10.10.10.0/24", self.policy)

    def test_network_and_broadcast_addresses_are_rejected(self):
        with self.assertRaises(PolicyError):
            validate_educational_target("10.10.10.0", self.policy)
        with self.assertRaises(PolicyError):
            validate_educational_target("10.10.10.255", self.policy)

    def test_policy_rejects_broad_or_public_networks(self):
        broad = dict(VALID_POLICY)
        broad["allowed_networks"] = ["10.0.0.0/8"]
        with self.assertRaises(PolicyError):
            policy_from_mapping(broad)

        public = dict(VALID_POLICY)
        public["allowed_networks"] = ["203.0.113.0/24"]
        with self.assertRaises(PolicyError):
            policy_from_mapping(public)

    def test_modes_and_profiles_are_separated(self):
        self.assertEqual(resolve_mode(False, self.policy, groups=[]), STUDENT_MODE)
        self.assertEqual(
            resolve_mode(True, self.policy, groups=["foxvuln-teachers"]),
            TEACHER_MODE,
        )
        with self.assertRaises(PolicyError):
            resolve_mode(True, self.policy, groups=["students"])
        self.assertEqual(allowed_profiles(self.policy, STUDENT_MODE), (STUDENT_PROFILE,))
        self.assertEqual(
            allowed_profiles(self.policy, TEACHER_MODE),
            (STUDENT_PROFILE, TEACHER_PROFILE),
        )

    def test_teacher_mode_requires_institutional_enablement(self):
        disabled = policy_from_mapping({**VALID_POLICY, "teacher_mode_enabled": False})
        with self.assertRaises(PolicyError):
            resolve_mode(True, disabled, groups=["foxvuln-teachers"])

    def test_load_policy_from_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "edu_policy.json"
            path.write_text(json.dumps(VALID_POLICY), encoding="utf-8")
            loaded = load_education_policy(path, require_secure=False)
            self.assertEqual(loaded.institution, "Escuela de prueba")
            self.assertEqual(loaded.source, str(path))
            self.assertEqual(len(loaded.sha256), 64)

    def test_teacher_config_reports_invalid_json_without_traceback(self):
        project_root = Path(__file__).resolve().parents[1]
        script = project_root / "configure_teacher_mode.sh"
        username = pwd.getpwuid(os.getuid()).pw_name
        with tempfile.TemporaryDirectory() as temp:
            invalid = Path(temp) / "invalid.json"
            invalid.write_text('{"schema_version": 1}\n]', encoding="utf-8")
            result = subprocess.run(
                ["bash", str(script), username, str(invalid)],
                cwd=project_root,
                text=True,
                capture_output=True,
                check=False,
            )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error de política:", output)
        self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main()
