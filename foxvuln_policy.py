#!/usr/bin/env python3
# Copyright (C) 2026 Luis Jofré Pérez
# SPDX-License-Identifier: GPL-3.0-or-later
"""Política de seguridad para FoxVuln EDU.

La edición educativa solo acepta un objetivo IPv4 incluido expresamente en la
allowlist del laboratorio. El modo docente se controla mediante pertenencia a
un grupo local de Linux y una política instalada por root.
"""
from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping

SYSTEM_POLICY_PATH = Path("/etc/foxvuln/edu_policy.json")
STUDENT_MODE = "student"
TEACHER_MODE = "teacher"
STUDENT_PROFILE = "Laboratorio educativo"
TEACHER_PROFILE = "Laboratorio avanzado (docente)"
KNOWN_PROFILES = (STUDENT_PROFILE, TEACHER_PROFILE)
RFC1918 = tuple(
    map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
)


class PolicyError(RuntimeError):
    """Error controlado de política educativa."""


@dataclass(frozen=True)
class EducationPolicy:
    schema_version: int
    institution: str
    laboratory: str
    allowed_networks: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    student_profiles: tuple[str, ...]
    teacher_profiles: tuple[str, ...]
    teacher_group: str
    teacher_mode_enabled: bool
    source: str = "built-in"
    sha256: str = ""

    def public_dict(self) -> dict:
        data = asdict(self)
        data["allowed_networks"] = list(self.allowed_networks)
        data["allowed_targets"] = list(self.allowed_targets)
        data["student_profiles"] = list(self.student_profiles)
        data["teacher_profiles"] = list(self.teacher_profiles)
        return data


DEFAULT_POLICY = EducationPolicy(
    schema_version=1,
    institution="Hackcop",
    laboratory="Laboratorio virtual local",
    allowed_networks=("192.168.56.0/24", "192.168.122.0/24"),
    allowed_targets=("127.0.0.1",),
    student_profiles=(STUDENT_PROFILE,),
    teacher_profiles=(STUDENT_PROFILE, TEACHER_PROFILE),
    teacher_group="foxvuln-teachers",
    teacher_mode_enabled=False,
)


def _canonical_digest(data: Mapping) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _as_string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"El campo '{field_name}' debe ser una lista de textos.")
    return tuple(item.strip() for item in value if item.strip())


def _validate_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PolicyError(f"Red educativa inválida: {value}") from exc
    if network.version != 4:
        raise PolicyError(f"Solo se permiten redes IPv4: {value}")
    if not any(network.subnet_of(private) for private in RFC1918):
        raise PolicyError(f"La red debe pertenecer a RFC1918: {value}")
    if network.prefixlen < 24:
        raise PolicyError(
            f"La red {value} es demasiado amplia para la edición EDU; use /24 o una red más pequeña."
        )
    return str(network)


def _validate_single_target(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PolicyError(f"Objetivo educativo inválido: {value}") from exc
    if address.version != 4:
        raise PolicyError(f"Solo se permiten objetivos IPv4: {value}")
    if not (address.is_loopback or any(address in network for network in RFC1918)):
        raise PolicyError(f"El objetivo debe ser loopback o RFC1918: {value}")
    return str(address)


def _validate_profiles(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    unknown = [name for name in values if name not in KNOWN_PROFILES]
    if unknown:
        raise PolicyError(f"{field_name} contiene perfiles desconocidos: {', '.join(unknown)}")
    return values


def policy_from_mapping(data: Mapping, source: str = "memory") -> EducationPolicy:
    try:
        schema_version = int(data.get("schema_version", 1))
        institution = str(data.get("institution", "Hackcop")).strip()
        laboratory = str(data.get("laboratory", "Laboratorio educativo")).strip()
        networks = _as_string_tuple(data.get("allowed_networks", []), "allowed_networks")
        targets = _as_string_tuple(data.get("allowed_targets", []), "allowed_targets")
        student_profiles = _as_string_tuple(
            data.get("student_profiles", [STUDENT_PROFILE]), "student_profiles"
        )
        teacher_profiles = _as_string_tuple(
            data.get("teacher_profiles", [STUDENT_PROFILE, TEACHER_PROFILE]),
            "teacher_profiles",
        )
        teacher_group = str(data.get("teacher_group", "foxvuln-teachers")).strip()
        teacher_mode_enabled = bool(data.get("teacher_mode_enabled", False))
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"Política EDU inválida: {exc}") from exc

    if schema_version != 1:
        raise PolicyError(f"Versión de esquema no compatible: {schema_version}")
    if not institution or not laboratory:
        raise PolicyError("Institution y laboratory no pueden quedar vacíos.")
    if not teacher_group or any(ch.isspace() for ch in teacher_group):
        raise PolicyError("teacher_group debe ser un nombre de grupo Linux válido.")

    normalized_networks = tuple(_validate_network(item) for item in networks)
    normalized_targets = tuple(_validate_single_target(item) for item in targets)
    if not normalized_networks and not normalized_targets:
        raise PolicyError("La política debe autorizar al menos una red o un objetivo individual.")

    student_profiles = _validate_profiles(student_profiles, "student_profiles")
    teacher_profiles = _validate_profiles(teacher_profiles, "teacher_profiles")
    if STUDENT_PROFILE not in student_profiles:
        raise PolicyError(f"student_profiles debe incluir '{STUDENT_PROFILE}'.")
    if STUDENT_PROFILE not in teacher_profiles:
        raise PolicyError(f"teacher_profiles debe incluir '{STUDENT_PROFILE}'.")

    canonical = {
        "schema_version": schema_version,
        "institution": institution,
        "laboratory": laboratory,
        "allowed_networks": list(normalized_networks),
        "allowed_targets": list(normalized_targets),
        "student_profiles": list(student_profiles),
        "teacher_profiles": list(teacher_profiles),
        "teacher_group": teacher_group,
        "teacher_mode_enabled": teacher_mode_enabled,
    }
    return EducationPolicy(
        schema_version=schema_version,
        institution=institution,
        laboratory=laboratory,
        allowed_networks=normalized_networks,
        allowed_targets=normalized_targets,
        student_profiles=student_profiles,
        teacher_profiles=teacher_profiles,
        teacher_group=teacher_group,
        teacher_mode_enabled=teacher_mode_enabled,
        source=source,
        sha256=_canonical_digest(canonical),
    )


def _assert_secure_policy_file(path: Path) -> None:
    info = path.stat()
    if info.st_uid != 0:
        raise PolicyError(f"La política {path} debe pertenecer a root.")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PolicyError(f"La política {path} no puede ser modificable por grupo u otros usuarios.")
    if not stat.S_ISREG(info.st_mode):
        raise PolicyError(f"La política {path} debe ser un archivo regular.")


def load_education_policy(
    path: Path | None = None,
    *,
    require_secure: bool | None = None,
) -> EducationPolicy:
    selected = Path(path) if path is not None else SYSTEM_POLICY_PATH
    if not selected.exists():
        if path is not None:
            raise PolicyError(f"No existe la política educativa: {selected}")
        data = DEFAULT_POLICY.public_dict()
        data.pop("source", None)
        data.pop("sha256", None)
        return policy_from_mapping(data, source="built-in")

    secure = (path is None) if require_secure is None else require_secure
    if secure:
        _assert_secure_policy_file(selected)
    try:
        raw = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"No fue posible leer la política {selected}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("La política EDU debe contener un objeto JSON.")
    return policy_from_mapping(raw, source=str(selected))


def current_group_names() -> set[str]:
    names: set[str] = set()
    try:
        primary_gid = os.getgid()
        gids = set(os.getgroups()) | {primary_gid}
        for entry in grp.getgrall():
            if entry.gr_gid in gids:
                names.add(entry.gr_name)
    except (KeyError, OSError):
        return names
    return names


def resolve_mode(
    teacher_requested: bool,
    policy: EducationPolicy,
    *,
    groups: Iterable[str] | None = None,
) -> str:
    if not teacher_requested:
        return STUDENT_MODE
    if not policy.teacher_mode_enabled:
        raise PolicyError(
            "El modo docente no está habilitado. Instale una política institucional con configure_teacher_mode.sh."
        )
    group_names = set(groups) if groups is not None else current_group_names()
    if policy.teacher_group not in group_names:
        raise PolicyError(
            f"El usuario actual no pertenece al grupo docente '{policy.teacher_group}'."
        )
    return TEACHER_MODE


def allowed_profiles(policy: EducationPolicy, mode: str) -> tuple[str, ...]:
    if mode == STUDENT_MODE:
        # La política puede restringir, pero nunca ampliar el modo estudiante.
        return tuple(name for name in policy.student_profiles if name == STUDENT_PROFILE)
    if mode == TEACHER_MODE:
        return tuple(name for name in policy.teacher_profiles if name in KNOWN_PROFILES)
    raise PolicyError(f"Modo educativo desconocido: {mode}")


def validate_educational_target(value: str, policy: EducationPolicy) -> str:
    raw = value.strip()
    if "/" in raw:
        raise PolicyError("Ingrese una sola dirección IPv4, sin CIDR.")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise PolicyError("Ingrese una dirección IPv4 válida, sin CIDR.") from exc
    if address.version != 4:
        raise PolicyError("La edición EDU solo acepta IPv4.")

    if str(address) in policy.allowed_targets:
        return str(address)

    for item in policy.allowed_networks:
        network = ipaddress.ip_network(item)
        if address not in network:
            continue
        if network.prefixlen <= 30 and address in {network.network_address, network.broadcast_address}:
            raise PolicyError(f"{address} es una dirección reservada de la red {network}.")
        return str(address)

    allowed = ", ".join((*policy.allowed_networks, *policy.allowed_targets))
    raise PolicyError(
        f"El objetivo {address} no pertenece a la allowlist del laboratorio. Permitidos: {allowed}."
    )
