# Parcial-3-Sistemas-Operativos


Este proyecto aborda un problema crítico de seguridad: cómo proteger archivos mapeados en memoria mediante `mmap()` evitando que los mecanismos de defensa sean evadidos en el espacio de usuario (Ring 3). La solución se implementa directamente en el corazón del sistema operativo (Ring 0).

## El Problema
Cuando un proceso mapea un archivo en memoria con `mmap()`, los accesos posteriores de lectura/escritura ocurren a velocidad de hardware directamente a través de la MMU (*Page Faults*). Esto significa que **ninguna herramienta en el espacio de usuario** (como envoltorios con `LD_PRELOAD` o rastreadores como `strace`) puede auditar o bloquear las modificaciones una vez que la página está cargada en memoria. 

## La Solución
Diseñé un Módulo del Kernel (LKM) que intercepta la llamada interna `security_mmap_file` utilizando **Kprobes**. 
En lugar de monitorear cada escritura (lo cual destruiría el rendimiento del sistema), interceptamos el momento exacto en que se va a crear la estructura de memoria virtual VMA (`vm_area_struct`). Si un proceso intenta mapear un archivo sensible ("archivo_secreto.txt") con permisos de escritura y de forma compartida (`PROT_WRITE` + `MAP_SHARED`), el kernel bloquea la operación antes de que se le asigne la memoria, protegiendo la integridad de los datos.

## Estructura del Repositorio
- `secure_mmap.c`: Código fuente del módulo del kernel (LKM) con el hook de intercepción (kprobes).
- `poc_test.c`: Programa en espacio de usuario (Proof of Concept) que simula a un atacante intentando vulnerar nuestro archivo.
- `Makefile`: Script para compilar el módulo del kernel contra las cabeceras de tu sistema.

## Cómo compilar y probar (Entorno Linux)

Compilar el módulo del kernel

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
