## 1.0.1-edu

- Documentación portable sin rutas personales.
- Uso de `$USER` en la configuración del modo docente.
- Correcciones menores de documentación.
- Sin cambios funcionales en el motor de análisis.

# Changelog

## 1.0.0-edu — 2026-07-12

- Se promueve FoxVuln EDU a versión educativa estable.
- Se establece `Hackcop` como institución predeterminada y en la política de ejemplo.
- Todos los hallazgos de demostración se atribuyen a `Simulador educativo`.
- Las políticas JSON inválidas se rechazan sin traceback de Python.
- Se agregan pruebas para branding, fuentes sintéticas y errores de política controlados.
- Se consolidan en un único paquete los modos estudiante y docente.

## 1.0.0-edu-rc.2 — 2026-07-12

- Se validó el perfil estudiante en Fedora contra una VM Kali aislada por red Host-only.
- Se tradujeron los estados visibles del informe y de los procesos externos.
- Se añadió una advertencia inequívoca a los informes de demostración sin tráfico.
- Se añadió una advertencia pedagógica a los análisis cancelados o incompletos.
- Se impidió anidar una ejecución dentro de una carpeta de resultados anterior.
- Se incorporaron pruebas automáticas para localización, cancelación y rutas de salida.
- Se mantuvo el estado interno canónico en JSON y se agregó su etiqueta localizada.

## 1.0.0-edu-rc.1 — 2026-07-11

- Se creó la edición educativa separada de la futura edición profesional.
- Se incorporó allowlist institucional con política JSON segura.
- Se limitó la allowlist a loopback o RFC1918, usando `/24` o subredes menores.
- Se rechazaron CIDR como objetivo, IP públicas y direcciones de red/broadcast.
- Se añadió modo estudiante con un único perfil conservador.
- Se añadió modo docente controlado por grupo Linux y política instalada por root.
- Se eliminó Nuclei de la edición EDU y de sus instaladores.
- Se corrigió el doble envoltorio TLS en la conexión SNI.
- Se incorporaron pruebas unitarias y de integración y un verificador de release.
- Se actualizaron informes, metadatos y documentación educativa.

## 0.1.3

- Base técnica anterior utilizada para construir la edición EDU.
