# Auditoría técnica — FoxVuln EDU 1.0.0-edu

## Dictamen

FoxVuln EDU 1.0.0-edu cumple el alcance definido para una edición educativa estable y supervisada. El modo estudiante, el modo docente, la política institucional, la cancelación, los informes y la integridad de evidencias fueron validados en un laboratorio Fedora–Kali aislado.

## Controles verificados

- Allowlist de loopback y redes privadas `/24` o menores.
- Rechazo de IP públicas, CIDR y direcciones de red o broadcast.
- Un objetivo por ejecución.
- Perfil estudiante limitado a 100 puertos, HTTP `HEAD` y comprobación TLS.
- Perfil docente limitado a 1.000 puertos y verificaciones integradas no destructivas.
- Sin Nuclei, explotación, fuerza bruta, fuzzing, evasión, DoS ni OAST.
- Terminación del grupo de procesos externos y conservación de evidencia parcial.
- Informes HTML, JSON y CSV con manifiesto SHA-256.
- Permisos locales restrictivos para carpetas y archivos.
- Modo docente sujeto a política instalada por `root` y pertenencia a grupo Linux.

## Correcciones finales

1. La identidad institucional predeterminada se establece en `Hackcop`.
2. Todas las detecciones de la demostración usan la fuente `Simulador educativo`.
3. Las políticas JSON inválidas se rechazan con un mensaje controlado, sin traceback.
4. El paquete y sus documentos se identifican como `1.0.0-edu` estable.
5. Se incorporan pruebas automáticas específicas para estos controles.

## Validación automática requerida

```bash
./verify_release.sh
```

El verificador compila los módulos, ejecuta todas las pruebas, valida la política JSON, revisa los scripts Bash y genera una demostración temporal sin tráfico.

## Recomendación de publicación

Publicar como release estable `v1.0.0-edu`, adjuntando el ZIP y su archivo SHA-256. Los modos estudiante y docente pertenecen a la misma edición y no deben publicarse como productos separados.
