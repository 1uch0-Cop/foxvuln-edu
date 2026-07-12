# Descarga, instalación y primera prueba

## Fedora

```bash
cd ~/Descargas
sha256sum -c FoxVuln_1.0.0-edu.zip.sha256
unzip FoxVuln_1.0.0-edu.zip
cd FoxVuln_1.0.0-edu
chmod +x *.sh
./install_fedora.sh
```

## Kali o Debian

```bash
chmod +x *.sh
./install_kali.sh
```

## Primera prueba

```bash
python3 foxvuln.py --version
python3 foxvuln.py --show-policy
python3 foxvuln.py --demo
```

## Interfaz gráfica

```bash
./run.sh
```

## Prueba real controlada

```bash
python3 foxvuln.py --cli \
  --target 192.168.56.101 \
  --profile "Laboratorio educativo" \
  --authorized
```

El objetivo debe pertenecer a la allowlist mostrada por `--show-policy`.

## Problemas frecuentes

### Objetivo fuera de la allowlist

No amplíe el código ni el rango. El docente debe añadir solamente la red virtual correcta a la política institucional.

### Tkinter no disponible en Fedora

```bash
sudo dnf install -y python3-tkinter
```

### Tkinter no disponible en Kali/Debian

```bash
sudo apt install -y python3-tk
```

### Modo docente denegado

Compruebe:

```bash
id
grep foxvuln /etc/group
ls -l /etc/foxvuln/edu_policy.json
```

Después de agregar el usuario al grupo es necesario cerrar la sesión y volver a ingresar.
