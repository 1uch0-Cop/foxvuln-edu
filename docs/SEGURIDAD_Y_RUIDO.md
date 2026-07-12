# Seguridad operativa y ruido

FoxVuln EDU no es silencioso. Nmap, HTTP, TLS, FTP y SMB pueden producir alertas en firewall, IDS, EDR, WAF, SIEM y registros del servidor.

## Perfil estudiante

- 100 puertos TCP frecuentes.
- Máximo 20 sondeos por segundo.
- Paralelismo 1.
- HTTP `HEAD`.
- Sin cuerpo HTTP, `OPTIONS`, FTP anónimo ni SMB avanzado.

## Perfil docente

- 1.000 puertos TCP frecuentes.
- Máximo 50 sondeos por segundo.
- Paralelismo 2.
- HTTP `GET`, captura máxima de 65.536 bytes y `OPTIONS`.
- Comprobación de FTP anónimo y scripts SMB seleccionados.

## Controles permanentes

- Un solo IPv4 por ejecución.
- Allowlist educativa.
- Sin rangos CIDR como objetivo.
- Sin IP públicas.
- Sin explotación, fuerza bruta, fuzzing, evasión, spoofing, DoS u OAST.
- Sin Nuclei en la edición EDU.
- Detención del grupo de procesos externos.
- Evidencias locales con permisos restrictivos cuando el sistema lo permite.

Un informe sin hallazgos no demuestra ausencia de vulnerabilidades; solo refleja el alcance ejecutado.
