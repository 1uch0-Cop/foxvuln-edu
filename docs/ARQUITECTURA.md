# Arquitectura de FoxVuln EDU

```text
foxvuln.py
 ├── carga política institucional
 ├── resuelve modo estudiante/docente
 ├── interfaz gráfica o CLI
 └── FoxVulnEngine
      ├── validación de allowlist
      ├── Nmap seguro
      ├── HTTP/TLS
      ├── FTP/SMB según perfil
      ├── clasificación de hallazgos
      └── informes y manifiesto SHA-256

foxvuln_policy.py
 ├── política integrada
 ├── lectura segura de /etc/foxvuln/edu_policy.json
 ├── validación de redes /24 o menores
 ├── control del grupo docente
 └── separación de perfiles
```

La interfaz nunca amplía la política. El motor vuelve a validar objetivo y perfil antes de crear la ejecución.

El modo docente requiere dos condiciones: `teacher_mode_enabled: true` y pertenencia al grupo Linux configurado. La política institucional debe estar controlada por `root`.

FoxVuln EDU conserva un núcleo local, sin cuentas, telemetría ni servicios externos.
