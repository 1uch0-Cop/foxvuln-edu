#!/usr/bin/env python3
# Copyright (C) 2026 Luis Jofré Pérez
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interfaz gráfica y CLI de FoxVuln."""
from __future__ import annotations

import argparse
import json
import queue
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from foxvuln_core import (
    APP,
    DEFAULT_PROFILE,
    PROFILES,
    VERSION,
    FoxVulnEngine,
    FoxVulnError,
    normalize_output_base,
)
from foxvuln_policy import (
    EducationPolicy,
    PolicyError,
    STUDENT_MODE,
    TEACHER_MODE,
    allowed_profiles,
    load_education_policy,
    resolve_mode,
)

BG, PANEL, ALT = "#030603", "#0a120a", "#101a10"
GREEN, CYAN, YELLOW, RED = "#00ff66", "#19e6e6", "#ffd166", "#ff4d6d"
TEXT, MUTED = "#dcffe6", "#7ea48a"


class FoxVulnGUI:
    def __init__(self, root: tk.Tk, policy: EducationPolicy, mode: str):
        self.root = root
        self.policy = policy
        self.mode = mode
        self.available_profiles = allowed_profiles(policy, mode)
        if not self.available_profiles:
            raise FoxVulnError("La política no habilita perfiles para el modo actual.")
        root.title(f"{APP} {VERSION}")
        root.geometry("1260x820")
        root.minsize(1040, 700)
        root.configure(bg=BG)
        self.target = tk.StringVar()
        self.domain = tk.StringVar()
        initial_profile = DEFAULT_PROFILE if DEFAULT_PROFILE in self.available_profiles else self.available_profiles[0]
        self.profile = tk.StringVar(value=initial_profile)
        self.profile_help = tk.StringVar(value=PROFILES[initial_profile].description)
        self.authorized = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="LISTO · SOLO OBJETIVOS AUTORIZADOS")
        self.progress_value = tk.DoubleVar(value=0)
        self.output_base = Path.home() / "CTF" / "foxvuln-edu"
        self.last_report: Path | None = None
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.current_engine: FoxVulnEngine | None = None
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._style()
        self._build()
        self.profile.trace_add("write", self._profile_changed)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._drain)

    def _style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT, font=("DejaVu Sans", 10))
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("Alt.TFrame", background=ALT)
        style.configure("Title.TLabel", background=PANEL, foreground=GREEN, font=("DejaVu Sans Mono", 22, "bold"))
        style.configure("Sub.TLabel", background=PANEL, foreground=CYAN, font=("DejaVu Sans Mono", 10))
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Status.TLabel", background=ALT, foreground=GREEN, font=("DejaVu Sans Mono", 10, "bold"))
        style.configure("Hack.TButton", background=ALT, foreground=GREEN, bordercolor=GREEN, padding=(12, 8), font=("DejaVu Sans Mono", 10, "bold"))
        style.configure("Danger.TButton", background=ALT, foreground=RED, bordercolor=RED, padding=(12, 8), font=("DejaVu Sans Mono", 10, "bold"))
        style.configure("Hack.TCheckbutton", background=PANEL, foreground=YELLOW, font=("DejaVu Sans Mono", 9))
        style.configure("Hack.Horizontal.TProgressbar", troughcolor="#071007", background=GREEN)
        style.configure("Treeview", background="#071007", fieldbackground="#071007", foreground=TEXT, rowheight=27)
        style.configure("Treeview.Heading", background=ALT, foreground=CYAN, font=("DejaVu Sans Mono", 9, "bold"))

    def _entry(self, parent, variable, color, width=22):
        return tk.Entry(
            parent,
            textvariable=variable,
            bg="#071007",
            fg=color,
            insertbackground=color,
            relief="flat",
            highlightthickness=1,
            highlightbackground="#225c32",
            highlightcolor=color,
            font=("DejaVu Sans Mono", 11),
            width=width,
        )

    def _build(self):
        header = ttk.Frame(self.root, style="Panel.TFrame", padding=16)
        header.pack(fill="x", padx=12, pady=(12, 6))
        left = ttk.Frame(header, style="Panel.TFrame")
        left.pack(side="left", fill="x", expand=True)
        mode_label = "DOCENTE" if self.mode == TEACHER_MODE else "ESTUDIANTE"
        ttk.Label(left, text="FOXVULN EDU // LABORATORIO SEGURO", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text=f"v{VERSION} · {self.policy.institution} · {self.policy.laboratory}", style="Sub.TLabel").pack(anchor="w")
        ttk.Label(header, text=f"MODO {mode_label} · ALLOWLIST · 1 HOST · SIN EXPLOTACIÓN", style="Status.TLabel", padding=(10, 8)).pack(side="right")

        controls = ttk.Frame(self.root, style="Panel.TFrame", padding=14)
        controls.pack(fill="x", padx=12, pady=6)
        ttk.Label(controls, text="Objetivo IPv4 del laboratorio:", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self._entry(controls, self.target, GREEN).grid(row=0, column=1, sticky="ew", padx=(0, 14), pady=4)
        ttk.Label(controls, text="Dominio/Host/SNI opcional:", style="Panel.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8), pady=4)
        self._entry(controls, self.domain, CYAN, 26).grid(row=0, column=3, sticky="ew", padx=(0, 14), pady=4)
        ttk.Label(controls, text="Perfil:", style="Panel.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(controls, textvariable=self.profile, state="readonly", values=self.available_profiles, width=34).grid(row=1, column=1, sticky="w", pady=4)
        ttk.Button(controls, text="Carpeta de resultados", style="Hack.TButton", command=self.choose_dir).grid(row=1, column=3, sticky="e", pady=4)
        ttk.Checkbutton(controls, text="Confirmo que el docente autorizó este objetivo de laboratorio", variable=self.authorized, style="Hack.TCheckbutton").grid(row=2, column=0, columnspan=4, sticky="w", pady=(10, 2))
        ttk.Label(controls, textvariable=self.profile_help, style="Muted.TLabel").grid(row=3, column=0, columnspan=4, sticky="w")
        allowlist = ", ".join((*self.policy.allowed_networks, *self.policy.allowed_targets))
        ttk.Label(controls, text=f"Allowlist activa: {allowlist}", style="Muted.TLabel").grid(row=4, column=0, columnspan=4, sticky="w")
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(3, weight=1)

        buttons = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 8))
        buttons.pack(fill="x", padx=12, pady=6)
        self.scan_button = ttk.Button(buttons, text="[1] Analizar objetivo", style="Hack.TButton", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(0, 8))
        self.demo_button = ttk.Button(buttons, text="[2] Ver demostración", style="Hack.TButton", command=self.start_demo)
        self.demo_button.pack(side="left", padx=8)
        self.stop_button = ttk.Button(buttons, text="[!] Detener", style="Danger.TButton", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        ttk.Button(buttons, text="[>] Abrir informe", style="Hack.TButton", command=self.open_report).pack(side="right")

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=12, pady=6)
        console_frame = ttk.Frame(body, style="Panel.TFrame", padding=8)
        findings_frame = ttk.Frame(body, style="Panel.TFrame", padding=8)
        body.add(console_frame, weight=3)
        body.add(findings_frame, weight=2)
        ttk.Label(console_frame, text="CONSOLA", style="Status.TLabel").pack(anchor="w")
        self.console = tk.Text(console_frame, bg="#010401", fg=GREEN, insertbackground=GREEN, font=("DejaVu Sans Mono", 9), wrap="word", relief="flat", highlightthickness=1, highlightbackground="#1f5c31", padx=10, pady=10)
        self.console.pack(fill="both", expand=True, pady=(6, 0))
        for tag, color in (("info", GREEN), ("cmd", CYAN), ("warn", YELLOW), ("error", RED), ("dim", MUTED)):
            self.console.tag_configure(tag, foreground=color)
        ttk.Label(findings_frame, text="RESULTADO", style="Status.TLabel").pack(anchor="w")
        self.tree = ttk.Treeview(findings_frame, columns=("sev", "title", "risk"), show="headings")
        for col, title, width in (("sev", "SEVERIDAD", 100), ("title", "HALLAZGO", 270), ("risk", "RIESGO", 70)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=(6, 0))

        footer = ttk.Frame(self.root, style="Alt.TFrame", padding=(12, 8))
        footer.pack(fill="x", padx=12, pady=(6, 12))
        ttk.Label(footer, textvariable=self.status, style="Status.TLabel").pack(side="left")
        ttk.Progressbar(footer, variable=self.progress_value, maximum=100, style="Hack.Horizontal.TProgressbar", length=330).pack(side="right")
        self._log(
            f"{APP} {VERSION} listo en modo {self.mode}. Política: {self.policy.source}\n",
            "dim",
        )

    def _profile_changed(self, *_):
        profile = PROFILES.get(self.profile.get())
        if profile:
            self.profile_help.set(f"{profile.description} Ruido: {profile.noise}.")

    def _log(self, text, level="info"):
        self.console.insert("end", text, level)
        self.console.see("end")

    def choose_dir(self):
        selected = filedialog.askdirectory(initialdir=str(self.output_base))
        if selected:
            chosen = Path(selected)
            normalized = normalize_output_base(chosen)
            self.output_base = normalized
            if normalized != chosen:
                messagebox.showinfo(
                    APP,
                    "Seleccionó una carpeta de una ejecución anterior. "
                    "FoxVuln usará su carpeta contenedora para evitar resultados anidados.",
                )
            self._log(f"Carpeta base: {normalized}\n", "info")

    def _set_running(self, running: bool):
        state = "disabled" if running else "normal"
        self.scan_button.configure(state=state)
        self.demo_button.configure(state=state)
        self.stop_button.configure(state="normal" if running else "disabled")

    def _engine(self):
        return FoxVulnEngine(
            self.output_base,
            log=lambda text, level="info": self.events.put(("log", (text, level))),
            progress=lambda value, text="": self.events.put(("progress", (value, text))),
            stop_requested=self.stop_event.is_set,
            policy=self.policy,
            mode=self.mode,
        )

    def start_scan(self):
        if not self.authorized.get():
            messagebox.showerror(APP, "Debe confirmar la autorización del docente para el objetivo.")
            return
        target = self.target.get().strip()
        if not target:
            messagebox.showerror(APP, "Ingrese un objetivo IPv4 incluido en la allowlist del laboratorio.")
            return
        profile = PROFILES[self.profile.get()]
        message = (
            f"Objetivo: {target}\n"
            f"Dominio/Host/SNI: {self.domain.get().strip() or 'No especificado'}\n"
            f"Perfil: {profile.name}\n"
            f"Ruido esperado: {profile.noise}\n\n"
            f"Modo: {self.mode}\n"
            "La evaluación generará tráfico y registros dentro del laboratorio. ¿Continuar?"
        )
        if not messagebox.askyesno("Confirmar alcance", message):
            return
        self._start(lambda engine: engine.run(target, self.domain.get(), self.profile.get()))

    def start_demo(self):
        self._start(lambda engine: engine.generate_demo())

    def _start(self, action):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self._set_running(True)
        self.progress_value.set(0)
        for item in self.tree.get_children():
            self.tree.delete(item)

        def worker():
            engine = self._engine()
            self.current_engine = engine
            try:
                report = action(engine)
                self.events.put(("complete", (report, engine.findings)))
            except InterruptedError as exc:
                self.events.put(("cancelled", str(exc)))
            except (FoxVulnError, OSError, RuntimeError) as exc:
                self.events.put(("error", str(exc)))
            except Exception as exc:
                self.events.put(("error", f"Error no previsto: {exc}"))
            finally:
                self.current_engine = None
                self.events.put(("idle", None))

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        if self.current_engine:
            threading.Thread(target=self.current_engine.request_stop, daemon=True).start()
        self.status.set("DETENCIÓN SOLICITADA")
        self._log("[!] Se solicitó detener la ejecución y el proceso externo activo.\n", "warn")

    def _close(self):
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno(APP, "Hay una ejecución activa. ¿Detenerla y cerrar?"):
                return
            self.stop_event.set()
            if self.current_engine:
                self.current_engine.request_stop()
        self.root.destroy()

    def open_report(self):
        if self.last_report and self.last_report.exists():
            webbrowser.open(self.last_report.as_uri())
        else:
            messagebox.showinfo(APP, "Todavía no existe un informe para abrir.")

    def _drain(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._log(*payload)
                elif kind == "progress":
                    value, text = payload
                    self.progress_value.set(value)
                    self.status.set(text.upper())
                elif kind == "complete":
                    report, findings = payload
                    self.last_report = report
                    labels = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFO"}
                    for finding in findings:
                        self.tree.insert("", "end", values=(labels.get(finding.severity, finding.severity), finding.title, finding.foxrisk))
                    self.status.set(f"COMPLETADO · {report.parent}")
                    self._log(f"\n[OK] Informe: {report}\n", "info")
                    webbrowser.open(report.as_uri())
                elif kind == "cancelled":
                    self._log(f"\n[CANCELADO] {payload}\n", "warn")
                    self.status.set("CANCELADO · EVIDENCIA PARCIAL CONSERVADA")
                    messagebox.showwarning(APP, str(payload))
                elif kind == "error":
                    self._log(f"\n[ERROR] {payload}\n", "error")
                    self.status.set("ERROR")
                    messagebox.showerror(APP, str(payload))
                elif kind == "idle":
                    self._set_running(False)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)


def cli_main(args, policy: EducationPolicy, mode: str):
    base = Path(args.output).expanduser()
    engine = FoxVulnEngine(
        base,
        log=lambda text, level="info": print(text, end=""),
        progress=lambda value, text="": print(f"[{value:3d}%] {text}"),
        policy=policy,
        mode=mode,
    )
    try:
        if args.demo:
            report = engine.generate_demo()
        else:
            if not args.authorized:
                raise SystemExit(
                    "Use --authorized únicamente cuando el docente haya autorizado el objetivo de laboratorio."
                )
            report = engine.run(args.target, args.domain, args.profile)
    except KeyboardInterrupt:
        engine.request_stop()
        raise SystemExit("Ejecución interrumpida por el operador.")
    except InterruptedError as exc:
        raise SystemExit(str(exc))
    except FoxVulnError as exc:
        raise SystemExit(f"Error: {exc}")
    print(f"Informe: {report}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "FoxVuln EDU: detección y clasificación segura en un único objetivo "
            "incluido en la allowlist del laboratorio."
        )
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--cli", action="store_true", help="Ejecutar sin interfaz gráfica")
    parser.add_argument("--demo", action="store_true", help="Generar un informe demostrativo sin tráfico")
    parser.add_argument("--target", default="", help="IPv4 autorizado por la política educativa")
    parser.add_argument("--domain", default="", help="Dominio para cabecera Host y SNI opcional")
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="Perfil educativo")
    parser.add_argument("--output", default="~/CTF/foxvuln-edu")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument(
        "--teacher",
        action="store_true",
        help="Solicitar modo docente; requiere política institucional y grupo Linux autorizado",
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help="Mostrar la política educativa efectiva y salir",
    )
    args = parser.parse_args()

    try:
        policy = load_education_policy()
        mode = resolve_mode(args.teacher, policy)
    except PolicyError as exc:
        parser.error(str(exc))

    permitted = allowed_profiles(policy, mode)
    if args.profile not in permitted:
        parser.error(
            f"El perfil '{args.profile}' no está permitido en modo {mode}. "
            f"Opciones: {', '.join(permitted)}"
        )

    if args.show_policy:
        payload = policy.public_dict()
        payload["effective_mode"] = mode
        payload["effective_profiles"] = list(permitted)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if args.cli or args.demo:
        cli_main(args, policy, mode)
        return
    root = tk.Tk()
    FoxVulnGUI(root, policy, mode)
    root.mainloop()


if __name__ == "__main__":
    main()
