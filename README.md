# FoxVuln EDU 1.0.0-edu

**Estado:** versión educativa estable  
**Institución:** Hackcop  
**Licencia:** GPL-3.0-or-later  
**Autor:** Luis Jofré Pérez

FoxVuln EDU es una herramienta de reconocimiento defensivo y clasificación técnica para laboratorios escolares, CTF formativos y actividades guiadas. Trabaja con un único objetivo IPv4 incluido expresamente en una allowlist de laboratorio.

No incorpora explotación automática, fuerza bruta, fuzzing, denegación de servicio, evasión, spoofing, OAST ni Nuclei. La herramienta genera tráfico detectable y debe utilizarse únicamente bajo supervisión y autorización.

## Modos

### Modo estudiante

- Perfil único: `Laboratorio educativo`.
- 100 puertos TCP frecuentes.
- Nmap TCP Connect con límite de 20 sondeos por segundo.
- HTTP `HEAD`, sin captura del cuerpo.
- Validación básica TLS.
- Sin `OPTIONS`, FTP anónimo, SMB avanzado ni Nuclei.

### Modo docente

- Requiere una política institucional instalada por `root`.
- Requiere pertenencia al grupo Linux definido en la política.
- Añade `Laboratorio avanzado (docente)`.
- Hasta 1.000 puertos TCP, `GET`, `OPTIONS`, FTP anónimo y comprobaciones SMB seleccionadas.
- Continúa sin explotación automática ni Nuclei.

## Allowlist predeterminada

Sin configuración institucional, FoxVuln EDU funciona en modo estudiante y acepta exclusivamente:

```text
192.168.56.0/24
192.168.122.0/24
127.0.0.1
```

Esto cubre laboratorios habituales de VirtualBox y libvirt. VMware u otras redes deben añadirse mediante la política institucional, usando redes `/24` o más pequeñas.

## Instalación en Fedora

```bash
chmod +x install_fedora.sh run.sh
./install_fedora.sh
./run.sh
```

## Instalación en Kali o Debian

```bash
chmod +x install_kali.sh run.sh
./install_kali.sh
./run.sh
```

## Demostración sin tráfico

```bash
python3 foxvuln.py --demo
```

Todos los hallazgos de la demostración usan la fuente `Simulador educativo` y se identifican expresamente como datos sintéticos.

## Mostrar política efectiva

```bash
python3 foxvuln.py --show-policy
```

## Ejecución CLI en modo estudiante

```bash
python3 foxvuln.py --cli \
  --target 192.168.56.101 \
  --profile "Laboratorio educativo" \
  --authorized
```

## Configurar modo docente

Primero edite una copia de la política:

```bash
cp config/edu_policy.example.json mi_laboratorio.json
nano mi_laboratorio.json
```

El ejemplo incluye `Hackcop` como institución. Después instálela y autorice al usuario docente:

```bash
./configure_teacher_mode.sh lucho mi_laboratorio.json
```

Una política JSON inválida se rechaza con un mensaje controlado y sin exponer un traceback de Python. Cierre la sesión y vuelva a entrar. Luego:

```bash
./run_teacher.sh
```

## Resultados

Los informes se guardan de forma predeterminada en:

```text
~/CTF/foxvuln-edu/<IP_FECHA_HORA>/
```

Incluyen `report.html`, `summary.json`, `findings.csv`, `commands.log`, evidencias técnicas y `manifest_sha256.json`.

## Verificación

```bash
./verify_release.sh
```

## Documentación

- `docs/GUIA_DESCARGA_INSTALACION.md`
- `docs/GUIA_DOCENTE.md`
- `docs/POLITICA_EDUCATIVA.md`
- `docs/SEGURIDAD_Y_RUIDO.md`
- `docs/ARQUITECTURA.md`
- `docs/PUBLICACION_GITHUB.md`
- `RELEASE_NOTES_1.0.0-edu.md`
- `AUDIT_1.0.0-edu.md`

La licencia permite estudiar, modificar y redistribuir el software. No concede autorización para evaluar sistemas ajenos.
