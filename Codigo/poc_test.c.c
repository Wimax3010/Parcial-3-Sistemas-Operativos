#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int fd;
    char *addr;

    // Crea el archivo de prueba
    system("echo 'Contenido ultra secreto' > archivo_secreto.txt");

    fd = open("archivo_secreto.txt", O_RDWR);
    if (fd == -1) {
        perror("Error abriendo el archivo");
        exit(EXIT_FAILURE);
    }

    printf("Intentando mmap() compartido y con permisos de escritura...\n");
    addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED) {
        printf("mmap() BLOQUEADO satisfactoriamente por el kernel.\n");
    } else {
        printf("mmap() Exitoso (Vulnerable). Datos: %s\n", addr);
        // Modificación directa evadiendo syscall write()
        addr[0] = 'X';
        munmap(addr, 4096);
    }

    close(fd);
    return 0;
}