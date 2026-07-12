# Guía docente

## 1. Preparar el laboratorio

Utilice una red virtual aislada o host-only. No conecte máquinas vulnerables directamente a la red administrativa ni a Internet.

Recomendación inicial:

```text
Docente/Fedora: 192.168.56.1
Objetivo de laboratorio: 192.168.56.101
Red autorizada: 192.168.56.0/24
```

## 2. Crear la política

```bash
cp config/edu_policy.example.json mi_laboratorio.json
nano mi_laboratorio.json
```

Registre únicamente redes destinadas al ejercicio. No agregue toda la red escolar por comodidad.

## 3. Habilitar al docente

```bash
./configure_teacher_mode.sh lucho mi_laboratorio.json
```

Después cierre la sesión y vuelva a entrar para aplicar el grupo Linux.

## 4. Comprobar la política

```bash
python3 foxvuln.py --show-policy
```

## 5. Ejecutar

Modo estudiante:

```bash
./run.sh
```

Modo docente:

```bash
./run_teacher.sh
```

## 6. Secuencia pedagógica sugerida

1. Generar la demostración sin tráfico.
2. Identificar servicios y diferenciar inventario de vulnerabilidad.
3. Revisar `00_scope.txt` y `commands.log`.
4. Ejecutar el perfil estudiante sobre una VM deliberadamente vulnerable.
5. Comparar evidencia, severidad, confianza y recomendación.
6. Mostrar el perfil avanzado únicamente como demostración docente.
7. Cerrar con autorización, alcance y tratamiento responsable de evidencias.

## 7. Después de la clase

- Elimine o archive de forma protegida los resultados.
- Apague las máquinas vulnerables.
- Revise que la red virtual no tenga puente hacia la infraestructura escolar.
- No publique informes con IP, dominios o configuraciones reales.
