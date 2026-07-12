# Política educativa de FoxVuln EDU

La política efectiva se carga desde `/etc/foxvuln/edu_policy.json`. Si el archivo no existe, se aplica una política integrada de modo estudiante.

## Requisitos de seguridad

El archivo institucional debe:

- pertenecer a `root`;
- no ser modificable por grupo ni otros usuarios;
- contener JSON válido;
- autorizar únicamente IPv4 loopback o redes RFC1918;
- limitar cada red a `/24` o una subred más pequeña;
- incluir al menos un objetivo o una red;
- utilizar exclusivamente los perfiles conocidos por la edición EDU.

FoxVuln se negará a iniciar si el archivo institucional existe, pero sus permisos o contenido son inseguros.

## Ejemplo

```json
{
  "schema_version": 1,
  "institution": "Hackcop",
  "laboratory": "Laboratorio virtual de ciberseguridad",
  "allowed_networks": ["192.168.56.0/24"],
  "allowed_targets": ["127.0.0.1"],
  "student_profiles": ["Laboratorio educativo"],
  "teacher_profiles": [
    "Laboratorio educativo",
    "Laboratorio avanzado (docente)"
  ],
  "teacher_group": "foxvuln-teachers",
  "teacher_mode_enabled": true
}
```

## Límite real del control

La política es una barrera operativa para un entorno escolar administrado; no es DRM. Como FoxVuln es software libre, una persona con permisos administrativos y capacidad para modificar el código puede crear otra versión. La seguridad institucional debe apoyarse también en cuentas sin privilegios, redes virtuales aisladas, reglas de firewall y supervisión docente.
