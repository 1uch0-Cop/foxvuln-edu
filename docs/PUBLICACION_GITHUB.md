# Publicación de FoxVuln EDU en GitHub

## Recomendación

Publicar un único repositorio para `FoxVuln EDU`. Los modos estudiante y docente forman parte de la misma edición, comparten núcleo, documentación y controles de seguridad.

Nombre sugerido del repositorio:

```text
foxvuln-edu
```

Release estable sugerida:

```text
v1.0.0-edu
```

Adjuntos de la release:

```text
FoxVuln_1.0.0-edu.zip
FoxVuln_1.0.0-edu.zip.sha256
```

## Qué no publicar todavía

La futura edición `FoxVuln Profesional Autorizado` no debe anunciarse como estable ni incluirse en la release educativa mientras no disponga de validador de alcance, ventanas temporales, allowlist contractual, auditoría de encargos y pruebas específicas.

Puede desarrollarse inicialmente en un repositorio privado o en una rama de desarrollo no publicada como release estable. Cuando alcance una versión alfa verificable, conviene decidir si se mantiene como edición separada o como un segundo repositorio.

## Estructura de ramas sugerida

```text
main                  versión educativa estable
release/1.x-edu       mantenimiento educativo
develop/2.0-pro       desarrollo profesional, sin release pública estable
```

No es necesario subir `rc.1` y `rc.2` como carpetas distintas. Git conserva el historial; opcionalmente pueden mantenerse como tags de pre-release.
