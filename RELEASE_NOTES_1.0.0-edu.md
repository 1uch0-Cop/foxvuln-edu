# FoxVuln EDU 1.0.0-edu

**Estado:** versión educativa estable.  
**Institución:** Hackcop.  
**Fecha:** 12 de julio de 2026.

## Alcance de la versión

FoxVuln EDU 1.0.0-edu consolida una edición separada para enseñanza supervisada. Incluye modo estudiante y modo docente dentro del mismo paquete, con una allowlist estricta y sin explotación automática.

## Cambios finales frente a rc.2

- La institución predeterminada y el ejemplo de política pasan a ser `Hackcop`.
- Todos los hallazgos de la demostración se atribuyen exclusivamente a `Simulador educativo`.
- Una política JSON inválida muestra un error breve y controlado, sin traceback de Python.
- El número de versión se promueve a `1.0.0-edu` estable.
- Las pruebas automáticas se amplían para cubrir el branding, las fuentes sintéticas y el manejo seguro de políticas inválidas.

## Validación operativa

La edición fue probada en Fedora contra una máquina Kali conectada mediante una red VirtualBox Host-only `192.168.56.0/24`.

Se validaron:

- demostración sin tráfico;
- modo estudiante;
- cancelación y conservación de evidencias parciales;
- detección de SSH en `22/tcp`;
- detección de HTTP en `8080/tcp`;
- perfil avanzado del modo docente;
- solicitudes HTTP `HEAD`, `GET` y `OPTIONS` según el perfil;
- informes HTML, JSON y CSV;
- manifiesto SHA-256;
- control de grupo Linux para el modo docente.

## Límites

- Un único IPv4 autorizado por ejecución.
- Sin objetivos públicos ni rangos CIDR.
- Sin explotación, fuerza bruta, fuzzing, evasión, DoS u OAST.
- Nuclei no está incluido en la edición EDU.
- El modo docente requiere política institucional y grupo Linux autorizado.
