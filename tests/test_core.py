# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import threading
import time
import unittest

from foxvuln_core import (
    DEFAULT_PROFILE,
    PROFILES,
    VERSION,
    FoxVulnEngine,
    FoxVulnError,
    Service,
    classify_cvss,
    normalize_output_base,
    validate_domain,
    validate_profile,
    validate_target,
)
from foxvuln_policy import (
    STUDENT_MODE,
    STUDENT_PROFILE,
    TEACHER_MODE,
    TEACHER_PROFILE,
    policy_from_mapping,
)


POLICY_DATA = {
    "schema_version": 1,
    "institution": "Escuela de prueba",
    "laboratory": "Laboratorio aislado",
    "allowed_networks": ["192.168.56.0/24"],
    "allowed_targets": ["127.0.0.1"],
    "student_profiles": [STUDENT_PROFILE],
    "teacher_profiles": [STUDENT_PROFILE, TEACHER_PROFILE],
    "teacher_group": "foxvuln-teachers",
    "teacher_mode_enabled": True,
}


class _FakeResponse:
    status = 200

    def getheaders(self):
        return [("Server", "demo"), ("Content-Type", "text/html")]

    def getheader(self, name, default=""):
        return default

    def read(self, amount=None):
        raise AssertionError("El perfil estudiante no debe leer el cuerpo HTTP")

    def close(self):
        pass


class _FakeConnection:
    def __init__(self):
        self.method = None
        self.headers = None

    def request(self, method, path, headers=None):
        self.method = method
        self.headers = headers or {}

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        pass


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy_from_mapping(POLICY_DATA, source="test")

    def test_target_obeys_educational_allowlist(self):
        self.assertEqual(validate_target("192.168.56.101", self.policy), "192.168.56.101")
        self.assertEqual(validate_target("127.0.0.1", self.policy), "127.0.0.1")
        with self.assertRaises(FoxVulnError):
            validate_target("10.10.10.10", self.policy)
        with self.assertRaises(FoxVulnError):
            validate_target("8.8.8.8", self.policy)

    def test_domain_and_profile_validation(self):
        self.assertEqual(validate_domain("Laboratorio.Local."), "laboratorio.local")
        self.assertEqual(
            validate_profile(DEFAULT_PROFILE, STUDENT_MODE, self.policy).name,
            STUDENT_PROFILE,
        )
        with self.assertRaises(FoxVulnError):
            validate_domain("dominio_invalido.local")
        with self.assertRaises(FoxVulnError):
            validate_profile(TEACHER_PROFILE, STUDENT_MODE, self.policy)
        self.assertEqual(
            validate_profile(TEACHER_PROFILE, TEACHER_MODE, self.policy).name,
            TEACHER_PROFILE,
        )

    def test_cvss(self):
        self.assertEqual(classify_cvss(9.8), "critical")
        self.assertEqual(classify_cvss(7.5), "high")
        self.assertEqual(classify_cvss(5.0), "medium")
        self.assertEqual(classify_cvss(2.0), "low")
        self.assertEqual(classify_cvss(0), "info")

    def test_https_not_classified_as_plain_http(self):
        service = Service(443, name="https", tunnel="ssl")
        self.assertTrue(FoxVulnEngine._is_https_service(service))
        self.assertFalse(FoxVulnEngine._is_http_service(service))

    def test_student_profile_uses_head_without_body(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = FoxVulnEngine(Path(temp), policy=self.policy, mode=STUDENT_MODE)
            engine._new_run("192.168.56.101", "laboratorio.local", DEFAULT_PROFILE)
            fake = _FakeConnection()
            engine._http_connection = lambda service, use_tls: fake  # type: ignore[method-assign]
            engine._check_http(Service(80, name="http"), use_tls=False)
            self.assertEqual(fake.method, "HEAD")
            evidence = (engine.run_dir / "02_http_80.txt").read_text(encoding="utf-8")
            self.assertIn("Method: HEAD", evidence)
            self.assertIn("Body bytes captured: 0", evidence)
            self.assertFalse((engine.run_dir / "03_http_options_80.txt").exists())

    def test_interruptible_process(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = FoxVulnEngine(Path(temp), policy=self.policy)
            engine._new_run("192.168.56.101", "", DEFAULT_PROFILE)
            timer = threading.Timer(0.25, engine.request_stop)
            timer.start()
            started = time.monotonic()
            with self.assertRaises(InterruptedError):
                engine.run_command(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    "sleep.txt",
                    timeout=10,
                )
            timer.cancel()
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(engine.commands[-1]["status"], "cancelled")

    def test_demo_report_manifest_and_educational_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = FoxVulnEngine(Path(temp), policy=self.policy)
            report = engine.generate_demo()
            self.assertTrue(report.exists())
            self.assertTrue((report.parent / "summary.json").exists())
            self.assertGreaterEqual(len(engine.findings), 5)
            summary = json.loads((report.parent / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["version"], VERSION)
            self.assertEqual(summary["edition"], "educational")
            self.assertEqual(summary["mode"], STUDENT_MODE)
            self.assertEqual(summary["policy"]["institution"], "Escuela de prueba")
            self.assertEqual(summary["profile"]["name"], "Demostración sin tráfico")
            manifest = json.loads((report.parent / "manifest_sha256.json").read_text(encoding="utf-8"))
            names = {item["file"] for item in manifest["files"]}
            self.assertNotIn("report.html", names)
            self.assertNotIn("manifest_sha256.json", names)
            html_text = report.read_text(encoding="utf-8")
            self.assertIn("FOXVULN EDU", html_text)
            self.assertIn("Escuela de prueba", html_text)
            self.assertIn("DEMOSTRACIÓN:", html_text)
            self.assertIn("No se generó tráfico de red", html_text)
            self.assertIn("COMPLETADO", html_text)
            self.assertEqual(summary["state_label"], "COMPLETADO")
            self.assertTrue(summary["demonstration"])
            self.assertTrue(summary["findings"])
            self.assertEqual(
                {finding["source"] for finding in summary["findings"]},
                {"Simulador educativo"},
            )

    def test_cancelled_report_warns_against_false_conclusions(self):
        with tempfile.TemporaryDirectory() as temp:
            engine = FoxVulnEngine(Path(temp), policy=self.policy)
            engine._new_run("192.168.56.101", "", DEFAULT_PROFILE)
            engine.run_state = "CANCELLED"
            report = engine._finish(partial=True)
            html_text = report.read_text(encoding="utf-8")
            self.assertIn("PARCIAL / CANCELADO", html_text)
            self.assertIn("ANÁLISIS INTERRUMPIDO", html_text)
            self.assertIn("no puede interpretarse como ausencia de exposición", html_text)

    def test_output_base_does_not_nest_inside_previous_result(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / "foxvuln-edu"
            previous = base / "192.168.56.101_20260712_003717_049162"
            previous.mkdir(parents=True)
            (previous / "report.html").write_text("demo", encoding="utf-8")
            self.assertEqual(normalize_output_base(previous), base)
            engine = FoxVulnEngine(previous, policy=self.policy)
            engine._new_run("192.168.56.101", "", DEFAULT_PROFILE)
            self.assertEqual(engine.run_dir.parent, base)

    def test_full_run_with_synthetic_nmap_process(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            fake_nmap = bin_dir / "nmap"
            fake_nmap.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import pathlib
                    import sys

                    args = sys.argv[1:]
                    xml = pathlib.Path(args[args.index("-oX") + 1])
                    normal = pathlib.Path(args[args.index("-oN") + 1])
                    xml.write_text(
                        '<nmaprun><host><status state="up"/><ports/></host></nmaprun>',
                        encoding="utf-8",
                    )
                    normal.write_text("Synthetic Nmap: no open ports\\n", encoding="utf-8")
                    print("Synthetic Nmap completed")
                    """
                ),
                encoding="utf-8",
            )
            fake_nmap.chmod(0o755)
            previous_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}:{previous_path}"
            try:
                engine = FoxVulnEngine(root / "out", policy=self.policy)
                report = engine.run("192.168.56.101", "", STUDENT_PROFILE)
            finally:
                os.environ["PATH"] = previous_path
            self.assertTrue(report.exists())
            self.assertEqual(engine.run_state, "COMPLETED")
            self.assertEqual(engine.commands[0]["status"], "completed")
            self.assertEqual(engine.commands[0]["status_label"], "completado")
            report_text = report.read_text(encoding="utf-8")
            self.assertIn("COMPLETADO", report_text)
            self.assertIn(">completado</td>", report_text)
            self.assertTrue(any("No se detectaron servicios" in item.title for item in engine.findings))

    def test_edu_profiles_never_enable_nuclei(self):
        self.assertEqual(set(PROFILES), {STUDENT_PROFILE, TEACHER_PROFILE})
        self.assertEqual(PROFILES[STUDENT_PROFILE].http_method, "HEAD")
        self.assertFalse(PROFILES[STUDENT_PROFILE].capture_http_body)
        self.assertFalse(PROFILES[STUDENT_PROFILE].http_options)
        self.assertFalse(PROFILES[STUDENT_PROFILE].ftp_anonymous)
        self.assertFalse(PROFILES[STUDENT_PROFILE].smb_checks)
        self.assertTrue(PROFILES[TEACHER_PROFILE].smb_checks)


if __name__ == "__main__":
    unittest.main()
