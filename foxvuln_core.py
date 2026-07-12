#!/usr/bin/env python3
# Copyright (C) 2026 Luis Jofré Pérez
# SPDX-License-Identifier: GPL-3.0-or-later
"""Motor seguro de FoxVuln EDU.

La edición educativa está restringida a un solo objetivo IPv4 incluido en la
allowlist del laboratorio. No incorpora explotación automática, fuerza bruta,
fuzzing, DoS, evasión, spoofing ni OAST.
"""
from __future__ import annotations

import csv
import ftplib
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from foxvuln_policy import (
    EducationPolicy,
    PolicyError,
    STUDENT_MODE,
    STUDENT_PROFILE,
    TEACHER_MODE,
    TEACHER_PROFILE,
    allowed_profiles,
    load_education_policy,
    resolve_mode,
    validate_educational_target,
)

APP = "FoxVuln EDU"
VERSION = "1.0.1-edu"
EDITION = "educational"
LICENSE_ID = "GPL-3.0-or-later"
USER_AGENT = f"FoxVuln-EDU/{VERSION} Educational-Lab"
HTTP_PORTS = {80, 8000, 8080, 8081, 8888}
HTTPS_PORTS = {443, 8443, 9443}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_LABEL = {
    "info": "Informativa",
    "low": "Baja",
    "medium": "Media",
    "high": "Alta",
    "critical": "Crítica",
}
RUN_STATE_LABEL = {
    "NOT_STARTED": "NO INICIADO",
    "RUNNING": "EN EJECUCIÓN",
    "COMPLETED": "COMPLETADO",
    "CANCELLED": "CANCELADO",
    "ERROR": "ERROR",
}
COMMAND_STATUS_LABEL = {
    "completed": "completado",
    "cancelled": "cancelado",
    "timeout": "tiempo agotado",
}


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    noise: str
    nmap_args: tuple[str, ...]
    http_method: str
    capture_http_body: bool
    http_options: bool
    ftp_anonymous: bool
    smb_checks: bool


PROFILES: dict[str, ScanProfile] = {
    STUDENT_PROFILE: ScanProfile(
        name=STUDENT_PROFILE,
        description="Revisión conservadora: 100 puertos TCP, HEAD y TLS.",
        noise="Bajo a moderado; detectable",
        nmap_args=(
            "--top-ports", "100",
            "--max-rate", "20",
            "--max-parallelism", "1",
            "--max-retries", "1",
            "-T2",
            "--version-intensity", "1",
        ),
        http_method="HEAD",
        capture_http_body=False,
        http_options=False,
        ftp_anonymous=False,
        smb_checks=False,
    ),
    TEACHER_PROFILE: ScanProfile(
        name=TEACHER_PROFILE,
        description="Inventario de 1.000 puertos y verificaciones integradas para demostración docente.",
        noise="Moderado; fácilmente detectable",
        nmap_args=(
            "--top-ports", "1000",
            "--max-rate", "50",
            "--max-parallelism", "2",
            "--max-retries", "2",
            "-T3",
            "--version-light",
        ),
        http_method="GET",
        capture_http_body=True,
        http_options=True,
        ftp_anonymous=True,
        smb_checks=True,
    ),
}
DEFAULT_PROFILE = STUDENT_PROFILE


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra: str = ""
    tunnel: str = ""
    cpes: list[str] = field(default_factory=list)
    confidence: int = 0

    @property
    def display(self) -> str:
        parts = [self.name]
        version_text = " ".join(x for x in (self.product, self.version, self.extra) if x)
        if version_text:
            parts.append(version_text)
        return " · ".join(parts)


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    confidence_score: int
    status: str
    target: str
    endpoint: str
    source: str
    description: str
    evidence: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    foxrisk: int = 0
    evidence_file: str = ""
    template_id: str = ""


class FoxVulnError(RuntimeError):
    """Error operativo controlado de FoxVuln."""


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    """Conecta a una IP y envía un SNI distinto cuando se indicó un dominio."""

    def __init__(self, connect_host: str, port: int, server_hostname: str, timeout: float, context: ssl.SSLContext):
        super().__init__(connect_host, port=port, timeout=timeout, context=context)
        self._fox_server_hostname = server_hostname

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self._fox_server_hostname)


def validate_target(value: str, policy: EducationPolicy | None = None) -> str:
    active_policy = policy or load_education_policy()
    try:
        return validate_educational_target(value, active_policy)
    except PolicyError as exc:
        raise FoxVulnError(str(exc)) from exc


def validate_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value:
        return ""
    if len(value) > 253:
        raise FoxVulnError("El dominio supera la longitud permitida.")
    pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not pattern.fullmatch(label) for label in value.split(".")):
        raise FoxVulnError("Dominio inválido. Ejemplo válido: laboratorio.local")
    return value


def validate_profile(
    value: str,
    mode: str = STUDENT_MODE,
    policy: EducationPolicy | None = None,
) -> ScanProfile:
    active_policy = policy or load_education_policy()
    permitted = allowed_profiles(active_policy, mode)
    if value not in permitted or value not in PROFILES:
        allowed = ", ".join(permitted) or "ninguno"
        raise FoxVulnError(f"Perfil no permitido en modo {mode}. Opciones: {allowed}.")
    return PROFILES[value]


def classify_cvss(score: Optional[float]) -> str:
    if score is None or score == 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def foxrisk_score(severity: str, confidence_score: int, cvss: Optional[float] = None) -> int:
    base = {"info": 5, "low": 25, "medium": 50, "high": 75, "critical": 92}.get(severity, 5)
    score = base + round((confidence_score - 50) * 0.18)
    if cvss is not None and cvss >= 9:
        score += 4
    return max(0, min(100, score))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _listify(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x not in (None, "")]
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value)]


def normalize_output_base(output_base: Path) -> Path:
    """Evita crear una ejecución dentro de otra carpeta de resultados."""
    candidate = Path(output_base).expanduser()
    if (candidate / "report.html").is_file() or (candidate / "summary.json").is_file():
        return candidate.parent
    return candidate


class FoxVulnEngine:
    def __init__(
        self,
        output_base: Path,
        log: Optional[Callable[[str, str], None]] = None,
        progress: Optional[Callable[[int, str], None]] = None,
        stop_requested: Optional[Callable[[], bool]] = None,
        policy: EducationPolicy | None = None,
        mode: str = STUDENT_MODE,
    ):
        self.output_base = normalize_output_base(output_base)
        self.policy = policy or load_education_policy()
        self.mode = mode
        if mode not in {STUDENT_MODE, TEACHER_MODE}:
            raise FoxVulnError(f"Modo educativo inválido: {mode}")
        if mode == TEACHER_MODE:
            try:
                resolve_mode(True, self.policy)
            except PolicyError as exc:
                raise FoxVulnError(str(exc)) from exc
        self.log_callback = log or (lambda text, level="info": None)
        self.progress_callback = progress or (lambda value, text="": None)
        self.external_stop_requested = stop_requested or (lambda: False)
        self._internal_stop = threading.Event()
        self._process_lock = threading.Lock()
        self._active_process: Optional[subprocess.Popen[str]] = None
        self.run_dir: Optional[Path] = None
        self.target = ""
        self.domain = ""
        self.profile_name = ""
        self.profile = PROFILES[DEFAULT_PROFILE]
        self.services: list[Service] = []
        self.findings: list[Finding] = []
        self.commands: list[dict] = []
        self.started_at = ""
        self.finished_at = ""
        self.run_state = "NOT_STARTED"
        self.is_demo = False
        self._finding_counter = 0

    def log(self, text: str, level: str = "info") -> None:
        self.log_callback(text, level)

    def progress(self, value: int, text: str) -> None:
        self.progress_callback(value, text)

    def _stop_is_requested(self) -> bool:
        return self._internal_stop.is_set() or bool(self.external_stop_requested())

    def _check_stop(self) -> None:
        if self._stop_is_requested():
            self._terminate_active_process()
            raise InterruptedError("Ejecución detenida por el usuario.")

    def request_stop(self) -> None:
        self._internal_stop.set()
        self._terminate_active_process()

    def _set_active_process(self, process: Optional[subprocess.Popen[str]]) -> None:
        with self._process_lock:
            self._active_process = process

    def _terminate_active_process(self, grace_seconds: float = 2.0) -> None:
        with self._process_lock:
            process = self._active_process
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=grace_seconds)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
        finally:
            with self._process_lock:
                if self._active_process is process:
                    self._active_process = None

    def _private_write_text(self, path: Path, text: str) -> None:
        path.write_text(text, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _new_run(
        self,
        target: str,
        domain: str,
        profile_name: str,
        *,
        enforce_policy: bool = True,
    ) -> None:
        self.target = validate_target(target, self.policy) if enforce_policy else str(ipaddress.ip_address(target))
        self.domain = validate_domain(domain)
        self.profile = validate_profile(profile_name, self.mode, self.policy)
        self.profile_name = self.profile.name
        self.services = []
        self.findings = []
        self.commands = []
        self._finding_counter = 0
        self._internal_stop.clear()
        self.is_demo = False
        now = datetime.now()
        self.started_at = now.isoformat(timespec="seconds")
        self.run_state = "RUNNING"
        self.run_dir = self.output_base / f"{self.target}_{now.strftime('%Y%m%d_%H%M%S_%f')}"
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        try:
            self.run_dir.chmod(0o700)
        except OSError:
            pass
        mode_label = "Docente" if self.mode == TEACHER_MODE else "Estudiante"
        scope = (
            f"{APP} {VERSION}\n"
            f"Licencia: {LICENSE_ID}\n"
            f"Edición: {EDITION}\n"
            f"Modo: {mode_label}\n"
            f"Institución: {self.policy.institution}\n"
            f"Laboratorio: {self.policy.laboratory}\n"
            f"Política: {self.policy.source}\n"
            f"SHA-256 política: {self.policy.sha256}\n"
            f"Allowlist: {', '.join((*self.policy.allowed_networks, *self.policy.allowed_targets))}\n"
            f"Inicio: {self.started_at}\n"
            f"Objetivo autorizado: {self.target}\n"
            f"Dominio/Host/SNI: {self.domain or 'No especificado'}\n"
            f"Perfil: {self.profile.name}\n"
            f"Descripción: {self.profile.description}\n"
            f"Ruido esperado: {self.profile.noise}\n"
            f"Método HTTP: {self.profile.http_method}\n"
            f"Captura de cuerpo HTTP: {'Sí, máximo 65536 bytes' if self.profile.capture_http_body else 'No'}\n"
            f"HTTP OPTIONS: {'Sí' if self.profile.http_options else 'No'}\n"
            f"FTP anónimo: {'Sí' if self.profile.ftp_anonymous else 'No'}\n"
            f"Scripts SMB: {'Sí' if self.profile.smb_checks else 'No'}\n"
            "Nuclei: No incluido en la edición EDU\n\n"
            "Límites: un host IPv4 incluido en la allowlist educativa; sin explotación; sin fuerza bruta; "
            "sin fuzzing; sin DoS; sin evasión; sin spoofing; sin OAST/Interactsh; "
            "sin plantillas de código, JavaScript, workflow o navegador headless.\n"
            "La allowlist técnica no sustituye la autorización y supervisión del docente.\n"
        )
        self._private_write_text(self.run_dir / "00_scope.txt", scope)

    def add_finding(
        self,
        title: str,
        severity: str,
        confidence: str,
        confidence_score: int,
        status: str,
        endpoint: str,
        source: str,
        description: str,
        evidence: str,
        recommendation: str,
        references: Optional[list[str]] = None,
        cves: Optional[list[str]] = None,
        cwes: Optional[list[str]] = None,
        cvss: Optional[float] = None,
        evidence_file: str = "",
        template_id: str = "",
    ) -> Finding:
        severity = severity.lower()
        if severity not in SEVERITY_ORDER:
            severity = classify_cvss(cvss)
        confidence_score = max(0, min(100, confidence_score))
        candidate_signature = (
            title.lower(), endpoint.lower(), tuple(sorted(cves or [])), template_id.lower()
        )
        for existing in self.findings:
            existing_signature = (
                existing.title.lower(), existing.endpoint.lower(),
                tuple(sorted(existing.cves)), existing.template_id.lower(),
            )
            if candidate_signature == existing_signature:
                return existing
        self._finding_counter += 1
        finding = Finding(
            finding_id=f"FOX-{self._finding_counter:04d}",
            title=title,
            severity=severity,
            confidence=confidence,
            confidence_score=confidence_score,
            status=status,
            target=self.target,
            endpoint=endpoint,
            source=source,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            references=references or [],
            cves=cves or [],
            cwes=cwes or [],
            cvss=cvss,
            foxrisk=foxrisk_score(severity, confidence_score, cvss),
            evidence_file=evidence_file,
            template_id=template_id,
        )
        self.findings.append(finding)
        return finding

    def _record_command(
        self,
        shown: str,
        exit_code: Optional[int],
        duration: float,
        evidence_name: str,
        status: str,
    ) -> None:
        item = {
            "command": shown,
            "exit_code": exit_code,
            "duration_seconds": duration,
            "evidence": evidence_name,
            "status": status,
            "status_label": COMMAND_STATUS_LABEL.get(status, status),
        }
        self.commands.append(item)
        if self.run_dir:
            line = (
                f"$ {shown}\nestado={COMMAND_STATUS_LABEL.get(status, status)} "
                f"salida={exit_code if exit_code is not None else 'n/a'} "
                f"duración={duration}s evidencia={evidence_name}\n\n"
            )
            log_path = self.run_dir / "commands.log"
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            try:
                log_path.chmod(0o600)
            except OSError:
                pass

    def run_command(self, args: list[str], evidence_name: str, timeout: int = 300) -> tuple[int, str]:
        self._check_stop()
        if not args or not shutil.which(args[0]):
            raise FoxVulnError(f"No se encontró la herramienta requerida: {args[0] if args else '(vacío)'}")
        if not self.run_dir:
            raise FoxVulnError("No existe una ejecución activa.")

        shown = shlex.join(args)
        self.log(f"$ {shown}\n", "cmd")
        started = time.monotonic()
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=(os.name == "posix"),
        )
        self._set_active_process(process)
        status = "completed"
        output = ""
        exit_code: Optional[int] = None
        try:
            while True:
                try:
                    output, _ = process.communicate(timeout=0.2)
                    exit_code = process.returncode
                    if self._stop_is_requested():
                        status = "cancelled"
                        raise InterruptedError("Ejecución detenida por el usuario.")
                    break
                except subprocess.TimeoutExpired:
                    if self._stop_is_requested():
                        status = "cancelled"
                        self._terminate_active_process()
                        output, _ = process.communicate()
                        exit_code = process.returncode
                        raise InterruptedError("Ejecución detenida por el usuario.")
                    if time.monotonic() - started >= timeout:
                        status = "timeout"
                        self._terminate_active_process()
                        output, _ = process.communicate()
                        exit_code = process.returncode
                        raise FoxVulnError(f"Tiempo agotado ejecutando {args[0]}.")
        except (InterruptedError, FoxVulnError):
            duration = round(time.monotonic() - started, 2)
            suffix = "\n[FOX] Ejecución cancelada.\n" if status == "cancelled" else "\n[FOX] Tiempo agotado.\n"
            self._private_write_text(self.run_dir / evidence_name, (output or "") + suffix)
            self._record_command(shown, exit_code, duration, evidence_name, status)
            raise
        finally:
            self._set_active_process(None)

        duration = round(time.monotonic() - started, 2)
        output = output or ""
        self._private_write_text(self.run_dir / evidence_name, output)
        self._record_command(shown, exit_code, duration, evidence_name, status)
        if output:
            self.log(output[-5000:] + ("\n" if not output.endswith("\n") else ""), "info")
        return int(exit_code or 0), output

    def run(self, target: str, domain: str = "", profile: str = DEFAULT_PROFILE) -> Path:
        self._new_run(target, domain, profile)
        try:
            self.progress(3, "Preparando alcance")
            self._run_nmap()
            self.progress(42, "Analizando servicios")
            self._run_builtin_checks()
            self.progress(90, "Generando informe")
            self.run_state = "COMPLETED"
            return self._finish(partial=False)
        except (InterruptedError, KeyboardInterrupt):
            self.request_stop()
            self.run_state = "CANCELLED"
            self._finish(partial=True)
            raise InterruptedError("Ejecución detenida; se conservaron las evidencias parciales.")
        except Exception:
            self.run_state = "ERROR"
            try:
                self._finish(partial=True)
            except Exception as finish_error:
                self.log(f"[!] No fue posible completar el informe parcial: {finish_error}\n", "warn")
            raise

    def _run_nmap(self) -> None:
        assert self.run_dir
        xml_path = self.run_dir / "01_nmap.xml"
        normal_path = self.run_dir / "01_nmap.txt"
        args = [
            "nmap", "-Pn", "-n", "-sT", "-sV", "--open",
            *self.profile.nmap_args,
            "--host-timeout", "5m",
            "-oX", str(xml_path), "-oN", str(normal_path), self.target,
        ]
        code, _ = self.run_command(args, "01_nmap_console.txt", timeout=330)
        if code != 0 or not xml_path.exists():
            raise FoxVulnError("Nmap no produjo un XML válido. Revise 01_nmap_console.txt.")
        self.services = self.parse_nmap_xml(xml_path)
        if not self.services:
            self.add_finding(
                "No se detectaron servicios TCP abiertos", "info", "Alta", 95,
                "Observado", self.target, "Nmap",
                "El escaneo TCP no encontró puertos abiertos dentro del alcance ejecutado.",
                "Nmap finalizó sin servicios TCP abiertos.",
                "Verifique conectividad, filtrado y alcance antes de ampliar la exploración.",
                evidence_file="01_nmap.xml",
            )

    @staticmethod
    def parse_nmap_xml(path: Path) -> list[Service]:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            raise FoxVulnError(f"No fue posible analizar el XML de Nmap: {exc}") from exc
        services: list[Service] = []
        for port_node in root.findall(".//host/ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_node = port_node.find("service")
            cpes = [node.text or "" for node in port_node.findall("service/cpe") if node.text]
            services.append(Service(
                port=int(port_node.get("portid", "0")),
                protocol=port_node.get("protocol", "tcp"),
                name=(service_node.get("name", "unknown") if service_node is not None else "unknown"),
                product=(service_node.get("product", "") if service_node is not None else ""),
                version=(service_node.get("version", "") if service_node is not None else ""),
                extra=(service_node.get("extrainfo", "") if service_node is not None else ""),
                tunnel=(service_node.get("tunnel", "") if service_node is not None else ""),
                cpes=cpes,
                confidence=int(service_node.get("conf", "0") or 0) if service_node is not None else 0,
            ))
        return sorted(services, key=lambda item: item.port)

    @staticmethod
    def _is_https_service(service: Service) -> bool:
        name = service.name.lower()
        return (
            service.port in HTTPS_PORTS
            or service.tunnel.lower() == "ssl"
            or name in {"https", "https-alt", "ssl/http"}
        )

    @classmethod
    def _is_http_service(cls, service: Service) -> bool:
        if cls._is_https_service(service):
            return False
        name = service.name.lower()
        return service.port in HTTP_PORTS or name == "http" or name.startswith("http-")

    def _run_builtin_checks(self) -> None:
        smb_needed = False
        for service in self.services:
            self._check_stop()
            if service.product or service.version:
                self.add_finding(
                    f"Servicio identificado: {service.display}", "info", "Media", 55,
                    "Inventario", f"{self.target}:{service.port}", "Nmap",
                    "Se identificó producto o versión. Una coincidencia de versión no confirma por sí sola una vulnerabilidad.",
                    service.display,
                    "Correlacione la versión con el proveedor y valide cualquier CVE mediante una comprobación específica no destructiva.",
                    evidence_file="01_nmap.xml",
                )

            if self._is_https_service(service):
                self._check_http(service, use_tls=True)
            elif self._is_http_service(service):
                self._check_http(service, use_tls=False)

            if service.port in TLS_PORTS or service.tunnel.lower() == "ssl":
                self._check_tls(service)
            if self.profile.ftp_anonymous and (service.port == 21 or service.name.lower() == "ftp"):
                self._check_ftp_anonymous(service)
            if self.profile.smb_checks and service.port in {139, 445}:
                smb_needed = True

        if smb_needed:
            self._check_smb()

    def _http_connection(self, service: Service, use_tls: bool):
        timeout = 6
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return _SNIHTTPSConnection(
                self.target,
                service.port,
                server_hostname=self.domain or self.target,
                timeout=timeout,
                context=context,
            )
        return http.client.HTTPConnection(self.target, service.port, timeout=timeout)

    def _check_http(self, service: Service, use_tls: bool) -> None:
        assert self.run_dir
        self._check_stop()
        scheme = "https" if use_tls else "http"
        endpoint = f"{scheme}://{self.target}:{service.port}/"
        host_header = self.domain or self.target
        method = self.profile.http_method
        evidence_lines = [
            f"Endpoint: {endpoint}",
            f"Host: {host_header}",
            f"SNI: {self.domain or self.target if use_tls else 'No aplica'}",
            f"Method: {method}",
            f"User-Agent: {USER_AGENT}",
        ]
        headers: dict[str, str] = {}
        body = b""
        try:
            conn = self._http_connection(service, use_tls)
            conn.request(method, "/", headers={"Host": host_header, "User-Agent": USER_AGENT})
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            if self.profile.capture_http_body and method == "GET":
                body = response.read(65536)
            response.close()
            conn.close()
            evidence_lines += [f"Status: {response.status}"] + [f"{k}: {v}" for k, v in headers.items()]
            evidence_lines.append(f"Body bytes captured: {len(body)}")
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            evidence_lines.append(f"Error HTTP: {exc}")
            filename = f"02_http_{service.port}.txt"
            self._private_write_text(self.run_dir / filename, "\n".join(evidence_lines) + "\n")
            return

        filename = f"02_http_{service.port}.txt"
        self._private_write_text(self.run_dir / filename, "\n".join(evidence_lines) + "\n")

        missing = []
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        csp = headers.get("content-security-policy", "")
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options / CSP frame-ancestors")
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if use_tls and "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
        if missing:
            self.add_finding(
                "Cabeceras de seguridad HTTP ausentes", "low", "Alta", 90,
                "Verificado", endpoint, "Motor FoxVuln",
                "La respuesta HTTP no incluye una o más cabeceras defensivas recomendadas. La relevancia depende del tipo de aplicación.",
                "Ausentes: " + ", ".join(missing),
                "Configure las cabeceras aplicables y valide que no interfieran con la funcionalidad legítima.",
                cwes=["CWE-693"], evidence_file=filename,
            )

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        disclosed = "; ".join(
            x for x in (f"Server: {server}" if server else "", f"X-Powered-By: {powered}" if powered else "") if x
        )
        if disclosed:
            self.add_finding(
                "Divulgación de tecnología mediante cabeceras HTTP", "info", "Alta", 95,
                "Verificado", endpoint, "Motor FoxVuln",
                "El servidor publica información de producto o plataforma que puede facilitar la enumeración.",
                disclosed,
                "Reduzca banners innecesarios, sin usar esta medida como sustituto de parches y configuración segura.",
                cwes=["CWE-200"], evidence_file=filename,
            )

        if self.profile.http_options:
            self._check_http_options(service, use_tls, endpoint, host_header)

    def _check_http_options(self, service: Service, use_tls: bool, endpoint: str, host_header: str) -> None:
        assert self.run_dir
        self._check_stop()
        options_file = f"03_http_options_{service.port}.txt"
        try:
            conn = self._http_connection(service, use_tls)
            conn.request("OPTIONS", "/", headers={"Host": host_header, "User-Agent": USER_AGENT})
            response = conn.getresponse()
            allow = response.getheader("Allow", "")
            status_opt = response.status
            response.read(4096)
            response.close()
            conn.close()
            self._private_write_text(
                self.run_dir / options_file,
                f"Method: OPTIONS\nStatus: {status_opt}\nAllow: {allow}\nUser-Agent: {USER_AGENT}\n",
            )
            methods = {x.strip().upper() for x in allow.split(",") if x.strip()}
            risky = sorted(methods & {"TRACE", "TRACK", "PUT", "DELETE"})
            if risky:
                severity = "medium" if {"PUT", "DELETE"} & set(risky) else "low"
                self.add_finding(
                    "Métodos HTTP potencialmente riesgosos habilitados", severity, "Media", 70,
                    "Requiere validación", endpoint, "Motor FoxVuln",
                    "El encabezado Allow anuncia métodos que requieren revisión de autorización y comportamiento real.",
                    "Métodos anunciados: " + ", ".join(risky),
                    "Deshabilite métodos no utilizados y compruebe controles de autorización antes de concluir impacto.",
                    cwes=["CWE-749"], evidence_file=options_file,
                )
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            self._private_write_text(self.run_dir / options_file, f"Error OPTIONS: {exc}\n")

    def _check_tls(self, service: Service) -> None:
        assert self.run_dir
        self._check_stop()
        endpoint = f"{self.target}:{service.port}"
        sni = self.domain or self.target
        filename = f"04_tls_{service.port}.txt"
        lines = [f"Endpoint: {endpoint}", f"SNI: {sni}"]
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, service.port), timeout=7) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
                    lines.append(f"TLS version: {tls_sock.version()}")
                    lines.append(f"Cipher: {tls_sock.cipher()}")
            if not der:
                raise ssl.SSLError("El servidor no entregó certificado.")
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
                handle.write(pem)
                temp_name = handle.name
            try:
                decoded = ssl._ssl._test_decode_cert(temp_name)  # type: ignore[attr-defined]
            finally:
                Path(temp_name).unlink(missing_ok=True)
            not_after = decoded.get("notAfter")
            not_before = decoded.get("notBefore")
            subject = decoded.get("subject")
            issuer = decoded.get("issuer")
            san = decoded.get("subjectAltName")
            lines += [
                f"Subject: {subject}", f"Issuer: {issuer}",
                f"SubjectAltName: {san}", f"Not Before: {not_before}", f"Not After: {not_after}",
            ]
            if not_after:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (expires - datetime.now(timezone.utc)).days
                lines.append(f"Days remaining: {days}")
                if days < 0:
                    severity, title = "high", "Certificado TLS vencido"
                elif days <= 30:
                    severity, title = "medium", "Certificado TLS próximo a vencer"
                elif days <= 90:
                    severity, title = "low", "Certificado TLS con vencimiento cercano"
                else:
                    severity, title = "", ""
                if severity:
                    self.add_finding(
                        title, severity, "Alta", 95, "Verificado", endpoint, "Motor FoxVuln",
                        "La vigencia observada del certificado requiere atención operativa.",
                        f"Días restantes: {days}; vencimiento: {not_after}",
                        "Renueve y despliegue el certificado antes del vencimiento; verifique la cadena completa.",
                        cwes=["CWE-324"], evidence_file=filename,
                    )
        except (OSError, ssl.SSLError, ValueError) as exc:
            lines.append(f"Error TLS: {exc}")
        self._private_write_text(self.run_dir / filename, "\n".join(lines) + "\n")

    def _check_ftp_anonymous(self, service: Service) -> None:
        assert self.run_dir
        self._check_stop()
        filename = f"05_ftp_anonymous_{service.port}.txt"
        evidence: list[str] = []
        ftp = ftplib.FTP()
        try:
            banner = ftp.connect(self.target, service.port, timeout=7)
            response = ftp.login("anonymous", "foxvuln@example.invalid")
            evidence += [banner, response]
            self.add_finding(
                "Acceso FTP anónimo habilitado", "medium", "Alta", 95,
                "Verificado", f"ftp://{self.target}:{service.port}", "Motor FoxVuln",
                "El servicio aceptó autenticación anónima. El impacto depende de los permisos efectivos.",
                response,
                "Deshabilite el acceso anónimo salvo necesidad documentada; limite permisos y supervise contenido expuesto.",
                cwes=["CWE-306"], evidence_file=filename,
            )
        except (OSError, ftplib.Error) as exc:
            evidence.append(f"No confirmado: {exc}")
        finally:
            try:
                ftp.close()
            except OSError:
                pass
        self._private_write_text(self.run_dir / filename, "\n".join(evidence) + "\n")

    def _check_smb(self) -> None:
        assert self.run_dir
        ports = sorted({s.port for s in self.services if s.port in {139, 445}})
        if not ports:
            return
        filename = "06_smb_security.txt"
        args = [
            "nmap", "-Pn", "-n", "-sT", "-p", ",".join(map(str, ports)),
            "--script", "smb-protocols,smb-security-mode,smb2-security-mode", self.target,
        ]
        code, output = self.run_command(args, filename, timeout=90)
        if code != 0:
            return
        lowered = output.lower()
        smb_endpoint = f"smb://{self.target}:{445 if 445 in ports else ports[0]}"
        if "message signing enabled but not required" in lowered or "message signing disabled" in lowered:
            self.add_finding(
                "Firma SMB no obligatoria", "medium", "Alta", 90,
                "Verificado", smb_endpoint, "Nmap NSE",
                "El servicio SMB no exige firma en todos los casos, lo que puede facilitar ataques de intermediario en redes no confiables.",
                "Nmap informó que la firma está deshabilitada o habilitada pero no es obligatoria.",
                "Exija firma SMB mediante la política correspondiente y confirme compatibilidad con clientes heredados.",
                cwes=["CWE-345"], evidence_file=filename,
            )
        if re.search(r"\bSMBv1\b", output, re.IGNORECASE) and not re.search(r"SMBv1[^\n]*disabled", output, re.IGNORECASE):
            self.add_finding(
                "SMBv1 detectado", "high", "Media", 75,
                "Requiere validación", smb_endpoint, "Nmap NSE",
                "Se observó soporte potencial para SMBv1, protocolo heredado con debilidades conocidas.",
                "La salida de smb-protocols contiene SMBv1 sin indicación de deshabilitado.",
                "Deshabilite SMBv1 y use SMBv2/SMBv3, tras validar dependencias heredadas.",
                cwes=["CWE-327"], evidence_file=filename,
            )

    def _finish(self, partial: bool = False) -> Path:
        assert self.run_dir
        self.finished_at = datetime.now().isoformat(timespec="seconds")
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.foxrisk), reverse=True)
        summary = {
            "application": APP,
            "version": VERSION,
            "edition": EDITION,
            "mode": self.mode,
            "policy": self.policy.public_dict(),
            "license": LICENSE_ID,
            "state": self.run_state,
            "state_label": RUN_STATE_LABEL.get(self.run_state, self.run_state),
            "partial": partial,
            "demonstration": self.is_demo,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": self.target,
            "domain": self.domain or None,
            "profile": asdict(self.profile),
            "services": [asdict(x) for x in self.services],
            "findings": [asdict(x) for x in self.findings],
            "commands": self.commands,
        }
        self._private_write_text(
            self.run_dir / "summary.json",
            json.dumps(summary, indent=2, ensure_ascii=False),
        )
        self._write_csv()
        self._write_manifest()
        report = self._write_html(partial)
        self._enforce_private_permissions()
        self.progress(100, "Completado" if not partial else "Informe parcial generado")
        return report

    def _write_csv(self) -> None:
        assert self.run_dir
        path = self.run_dir / "findings.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "ID", "Título", "Severidad", "Confianza", "Estado", "Endpoint",
                "CVE", "CWE", "CVSS", "FoxRisk", "Fuente", "Evidencia",
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.finding_id, finding.title, SEVERITY_LABEL[finding.severity],
                    finding.confidence, finding.status, finding.endpoint,
                    ", ".join(finding.cves), ", ".join(finding.cwes),
                    finding.cvss if finding.cvss is not None else "",
                    finding.foxrisk, finding.source, finding.evidence_file,
                ])
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _write_manifest(self) -> None:
        assert self.run_dir
        entries = []
        for path in sorted(self.run_dir.iterdir()):
            if path.is_file() and path.name not in {"manifest_sha256.json", "report.html"}:
                entries.append({"file": path.name, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        manifest = {
            "application": APP,
            "version": VERSION,
            "algorithm": "SHA-256",
            "scope": "Evidencias y exportaciones; report.html y el propio manifiesto quedan excluidos para evitar dependencia circular.",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "files": entries,
        }
        self._private_write_text(
            self.run_dir / "manifest_sha256.json",
            json.dumps(manifest, indent=2, ensure_ascii=False),
        )

    def _enforce_private_permissions(self) -> None:
        assert self.run_dir
        try:
            self.run_dir.chmod(0o700)
        except OSError:
            pass
        for path in self.run_dir.iterdir():
            if path.is_file():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def _write_html(self, partial: bool) -> Path:
        assert self.run_dir
        mode_label = "Docente" if self.mode == TEACHER_MODE else "Estudiante"
        counts = {key: sum(1 for finding in self.findings if finding.severity == key) for key in SEVERITY_ORDER}
        services_rows = "".join(
            "<tr>"
            f"<td>{service.port}/{html.escape(service.protocol)}</td>"
            f"<td>{html.escape(service.name)}</td>"
            f"<td>{html.escape(service.product)}</td>"
            f"<td>{html.escape(service.version)}</td>"
            f"<td>{html.escape(service.tunnel or '—')}</td>"
            f"<td>{html.escape(', '.join(service.cpes))}</td>"
            "</tr>"
            for service in self.services
        ) or '<tr><td colspan="6">Sin servicios abiertos registrados.</td></tr>'

        finding_cards = []
        for finding in self.findings:
            refs = "".join(
                f'<li><a href="{html.escape(ref)}" rel="noopener noreferrer">{html.escape(ref)}</a></li>'
                for ref in finding.references if ref.startswith(("http://", "https://"))
            )
            evidence_link = (
                f'<a href="{html.escape(finding.evidence_file)}">{html.escape(finding.evidence_file)}</a>'
                if finding.evidence_file else "Sin archivo específico"
            )
            search_text = (finding.title + " " + finding.endpoint + " " + " ".join(finding.cves)).lower()
            finding_cards.append(f"""
<article class="finding sev-{finding.severity}" data-severity="{finding.severity}" data-text="{html.escape(search_text)}">
  <div class="finding-head"><div><span class="badge">{html.escape(SEVERITY_LABEL[finding.severity])}</span> <b>{html.escape(finding.finding_id)}</b><h3>{html.escape(finding.title)}</h3></div><div class="risk">FoxRisk <strong>{finding.foxrisk}</strong>/100</div></div>
  <div class="meta"><span><b>Endpoint:</b> {html.escape(finding.endpoint)}</span><span><b>Estado:</b> {html.escape(finding.status)}</span><span><b>Confianza:</b> {html.escape(finding.confidence)} ({finding.confidence_score}%)</span><span><b>Fuente:</b> {html.escape(finding.source)}</span></div>
  <p>{html.escape(finding.description)}</p>
  <details><summary>Evidencia y tratamiento</summary><p><b>Evidencia:</b> {html.escape(finding.evidence)}</p><p><b>Archivo:</b> {evidence_link}</p><p><b>Recomendación:</b> {html.escape(finding.recommendation)}</p><p><b>CVE:</b> {html.escape(', '.join(finding.cves) or 'No informado')} · <b>CWE:</b> {html.escape(', '.join(finding.cwes) or 'No informado')} · <b>CVSS:</b> {html.escape(str(finding.cvss) if finding.cvss is not None else 'No informado')}</p>{('<ul>'+refs+'</ul>') if refs else ''}</details>
</article>""")

        evidence_items = "".join(
            f'<li><a href="{html.escape(path.name)}">{html.escape(path.name)}</a> <small>{path.stat().st_size} bytes</small></li>'
            for path in sorted(self.run_dir.iterdir()) if path.is_file() and path.name != "report.html"
        )
        command_rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(item.get('status_label') or COMMAND_STATUS_LABEL.get(str(item.get('status', '')), str(item.get('status', '')))))}</td>"
            f"<td>{html.escape(str(item.get('exit_code', '')))}</td>"
            f"<td>{html.escape(str(item.get('duration_seconds', '')))} s</td>"
            f"<td><code>{html.escape(str(item.get('command', '')))}</code></td>"
            "</tr>"
            for item in self.commands
        ) or '<tr><td colspan="4">Sin procesos externos registrados.</td></tr>'
        localized_state = RUN_STATE_LABEL.get(self.run_state, self.run_state)
        state_label = "PARCIAL / " + localized_state if partial else localized_state
        if self.is_demo:
            context_notice = (
                '<section class="card demo-warning"><b>DEMOSTRACIÓN:</b> '
                'todos los objetivos, servicios y hallazgos de este informe son sintéticos. '
                'No se generó tráfico de red.</section>'
            )
        elif self.run_state == "CANCELLED":
            context_notice = (
                '<section class="card warning"><b>ANÁLISIS INTERRUMPIDO:</b> '
                'la ausencia de servicios o hallazgos no puede interpretarse como ausencia de exposición. '
                'Revise las evidencias parciales antes de obtener conclusiones.</section>'
            )
        elif self.run_state == "ERROR":
            context_notice = (
                '<section class="card warning"><b>ANÁLISIS INCOMPLETO:</b> '
                'se produjo un error operativo. Revise las evidencias y el registro de comandos.</section>'
            )
        else:
            context_notice = ""

        page = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP} {VERSION} · {html.escape(self.target)}</title>
<style>
:root{{--bg:#030603;--panel:#091109;--alt:#101a10;--text:#dcffe6;--muted:#83a88e;--green:#00ff66;--cyan:#19e6e6;--border:#245b32;--info:#6ecbff;--low:#86e57f;--medium:#ffd166;--high:#ff8c42;--critical:#ff4d6d}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}} header{{position:sticky;top:0;background:rgba(3,6,3,.96);border-bottom:1px solid var(--border);z-index:5}} .wrap{{max-width:1220px;margin:auto;padding:18px}} h1{{color:var(--green);margin:.1rem 0}} h2{{color:var(--cyan)}} h3{{margin:.35rem 0}} a{{color:var(--cyan)}} code{{color:var(--green);white-space:pre-wrap;word-break:break-word}} .subtitle,.muted,small{{color:var(--muted)}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}} .metric,.card,.finding{{background:var(--panel);border:1px solid var(--border);border-radius:9px;padding:15px}} .metric strong{{display:block;font-size:25px}} .toolbar{{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}} input,button{{background:#071007;color:var(--text);border:1px solid var(--border);padding:9px 11px;border-radius:6px}} button{{cursor:pointer}} table{{width:100%;border-collapse:collapse}} th,td{{border:1px solid var(--border);padding:8px;text-align:left;vertical-align:top}} th{{color:var(--cyan);background:var(--alt)}} .finding{{margin:12px 0;border-left-width:5px}} .sev-info{{border-left-color:var(--info)}} .sev-low{{border-left-color:var(--low)}} .sev-medium{{border-left-color:var(--medium)}} .sev-high{{border-left-color:var(--high)}} .sev-critical{{border-left-color:var(--critical)}} .finding-head{{display:flex;justify-content:space-between;gap:14px}} .badge{{padding:3px 8px;border-radius:999px;background:var(--alt)}} .risk{{white-space:nowrap}} .risk strong{{font-size:24px}} .meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px;color:var(--muted)}} details{{border-top:1px solid var(--border);margin-top:10px;padding-top:8px}} summary{{cursor:pointer;color:var(--cyan)}} .warning{{border-color:var(--medium);color:#ffe8a8}} .demo-warning{{border-color:var(--cyan);color:#bffcff;background:#071313}} ul.files{{columns:2}} footer{{margin-top:24px;border-top:1px solid var(--border)}} @media(max-width:720px){{ul.files{{columns:1}} .finding-head{{display:block}} header{{position:static}}}} @media print{{header,.toolbar{{display:none}} body{{background:white;color:black}} .card,.finding,.metric{{border:1px solid #999;background:white}} a,code{{color:black}}}}
</style></head><body>
<header><div class="wrap"><h1>FOXVULN EDU // LABORATORIO SEGURO</h1><div class="subtitle">v{VERSION} · modo {html.escape(mode_label)} · aprendizaje con evidencia · sin explotación automática</div></div></header>
<main class="wrap">
<section class="card {'warning' if partial else ''}"><b>Institución:</b> {html.escape(self.policy.institution)} · <b>Laboratorio:</b> {html.escape(self.policy.laboratory)} · <b>Modo:</b> {html.escape(mode_label)}<br><b>Objetivo:</b> {html.escape(self.target)} · <b>Dominio/Host/SNI:</b> {html.escape(self.domain or 'No especificado')} · <b>Perfil:</b> {html.escape(self.profile.name)}<br><b>Inicio:</b> {html.escape(self.started_at)} · <b>Fin:</b> {html.escape(self.finished_at)} · <b>Estado:</b> {html.escape(state_label)}<p class="muted">Una coincidencia automatizada no sustituye la validación manual. “Inventario”, “requiere validación” y “detección probable” no equivalen a explotación confirmada.</p></section>
{context_notice}
<section><h2>Resumen</h2><div class="grid"><div class="metric"><span>Críticas</span><strong>{counts['critical']}</strong></div><div class="metric"><span>Altas</span><strong>{counts['high']}</strong></div><div class="metric"><span>Medias</span><strong>{counts['medium']}</strong></div><div class="metric"><span>Bajas</span><strong>{counts['low']}</strong></div><div class="metric"><span>Informativas</span><strong>{counts['info']}</strong></div><div class="metric"><span>Servicios</span><strong>{len(self.services)}</strong></div></div></section>
<section><h2>Perfil ejecutado</h2><div class="card"><b>{html.escape(self.profile.name)}</b> · {html.escape(self.profile.noise)}<p>{html.escape(self.profile.description)}</p><p class="muted">HTTP {html.escape(self.profile.http_method)} · Cuerpo: {'máx. 65.536 bytes' if self.profile.capture_http_body else 'no capturado'} · OPTIONS: {'sí' if self.profile.http_options else 'no'} · FTP anónimo: {'sí' if self.profile.ftp_anonymous else 'no'} · SMB: {'sí' if self.profile.smb_checks else 'no'} · Nuclei: no incluido</p></div></section>
<section><h2>Servicios</h2><div class="card" style="overflow:auto"><table><thead><tr><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Versión</th><th>Túnel</th><th>CPE</th></tr></thead><tbody>{services_rows}</tbody></table></div></section>
<section><h2>Hallazgos</h2><div class="toolbar"><input id="search" placeholder="Buscar título, endpoint o CVE" oninput="filterFindings()"><button onclick="setSeverity('all')">Todos</button><button onclick="setSeverity('critical')">Críticas</button><button onclick="setSeverity('high')">Altas</button><button onclick="setSeverity('medium')">Medias</button><button onclick="setSeverity('low')">Bajas</button><button onclick="setSeverity('info')">Informativas</button><button onclick="window.print()">Imprimir/PDF</button></div><div id="findings">{''.join(finding_cards) or '<div class="card">Sin hallazgos registrados.</div>'}</div></section>
<section><h2>Procesos externos</h2><div class="card" style="overflow:auto"><table><thead><tr><th>Estado</th><th>Código de salida</th><th>Duración</th><th>Comando</th></tr></thead><tbody>{command_rows}</tbody></table></div></section>
<section><h2>Evidencias</h2><div class="card"><ul class="files">{evidence_items}</ul><p class="muted">El manifiesto SHA-256 cubre evidencias y exportaciones; excluye report.html y el propio manifiesto para evitar dependencia circular.</p></div></section>
<footer class="wrap muted">{APP} {VERSION} · © 2026 Luis Jofré Pérez · {LICENSE_ID} · Uso educativo supervisado.</footer>
</main>
<script>let selected='all';function setSeverity(s){{selected=s;filterFindings()}}function filterFindings(){{const q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('.finding').forEach(x=>{{const okS=selected==='all'||x.dataset.severity===selected;const okQ=!q||x.dataset.text.includes(q);x.style.display=okS&&okQ?'block':'none'}})}}</script>
</body></html>"""
        report = self.run_dir / "report.html"
        self._private_write_text(report, page)
        return report

    def generate_demo(self) -> Path:
        self._new_run(
            "192.168.56.101",
            "laboratorio.local",
            DEFAULT_PROFILE,
            enforce_policy=False,
        )
        self.is_demo = True
        self.profile = ScanProfile(
            name="Demostración sin tráfico",
            description="Datos sintéticos para revisar el formato; no se generan conexiones de red.",
            noise="Nulo",
            nmap_args=(),
            http_method="N/A",
            capture_http_body=False,
            http_options=False,
            ftp_anonymous=False,
            smb_checks=False,
        )
        self.profile_name = self.profile.name
        self._private_write_text(
            self.run_dir / "00_scope.txt",
            f"{APP} {VERSION}\nLicencia: {LICENSE_ID}\nEdición: {EDITION}\nModo: {'Docente' if self.mode == TEACHER_MODE else 'Estudiante'}\nPerfil: Demostración sin tráfico\n"
            "Objetivo y hallazgos: sintéticos\nTráfico generado: ninguno\n",
        )
        self.run_state = "COMPLETED"
        self.services = [
            Service(21, name="ftp", product="vsftpd", version="2.3.4", confidence=10),
            Service(80, name="http", product="Apache httpd", version="2.4.x", confidence=10),
            Service(443, name="https", product="nginx", version="1.x", tunnel="ssl", confidence=9),
            Service(445, name="microsoft-ds", product="Samba smbd", version="4.x", confidence=8),
        ]
        self._private_write_text(
            self.run_dir / "demo_evidence.txt",
            "Evidencia sintética para mostrar el formato. No corresponde a un objetivo real.\n",
        )
        self.add_finding(
            "Acceso FTP anónimo habilitado", "medium", "Alta", 95, "Verificado",
            "ftp://192.168.56.101:21", "Simulador educativo", "El servicio aceptó acceso anónimo.",
            "230 Login successful.", "Deshabilitar acceso anónimo o limitarlo estrictamente.",
            cwes=["CWE-306"], evidence_file="demo_evidence.txt",
        )
        self.add_finding(
            "Firma SMB no obligatoria", "medium", "Alta", 90, "Verificado",
            "smb://192.168.56.101:445", "Simulador educativo", "La firma SMB no es obligatoria.",
            "Message signing enabled but not required.", "Exigir firma SMB y revisar compatibilidad.",
            cwes=["CWE-345"], evidence_file="demo_evidence.txt",
        )
        self.add_finding(
            "Cabeceras de seguridad HTTP ausentes", "low", "Alta", 90, "Verificado",
            "http://192.168.56.101:80/", "Simulador educativo", "Faltan cabeceras defensivas.",
            "Content-Security-Policy, X-Content-Type-Options.", "Configurar las cabeceras aplicables.",
            cwes=["CWE-693"], evidence_file="demo_evidence.txt",
        )
        self.add_finding(
            "Coincidencia automatizada de demostración", "high", "Alta", 82,
            "Detección automatizada probable", "https://192.168.56.101:443/", "Simulador educativo",
            "Ejemplo sintético de una detección automatizada que requiere validación manual.", "Regla: EDU-DEMO-0001",
            "Validar manualmente y actualizar según el proveedor.", cves=["CVE-DEMO-0001"],
            cvss=8.8, evidence_file="demo_evidence.txt", template_id="EDU-DEMO-0001",
        )
        self.add_finding(
            "Servicio identificado: Apache httpd 2.4.x", "info", "Media", 55, "Inventario",
            "192.168.56.101:80", "Simulador educativo", "La versión observada no confirma una vulnerabilidad.",
            "Apache httpd 2.4.x", "Correlacionar y validar CVE específicas.",
            evidence_file="demo_evidence.txt",
        )
        return self._finish(partial=False)
